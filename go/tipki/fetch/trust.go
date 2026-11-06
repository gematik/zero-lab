// Copyright (Change Date see Readme), gematik GmbH
//
// Licensed under the EUPL, Version 1.2 or - as soon they will be approved by the
// European Commission – subsequent versions of the EUPL (the "Licence").
// You may not use this work except in compliance with the Licence.
//
// You find a copy of the Licence in the "Licence" file or at
// https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the Licence is distributed on an "AS IS" basis,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either expressed or implied.
// In case of changes by gematik find details in the "Readme" file.
//
// See the Licence for the specific language governing permissions and limitations under the Licence.
//
// *******
//
// For additional notes and disclaimer from gematik and in case of changes by gematik,
// find details in the "Readme" file.

package fetch

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gematik/zero-lab/go/tipki"
	"github.com/gematik/zero-lab/go/tipki/titls"
)

const (
	// fetchEvery is the usual time between refreshes: the signer's .ocsp is renewed hourly.
	fetchEvery = time.Hour
	// fetchRetry is the time to the next attempt after one failed.
	fetchRetry = 5 * time.Minute
	// fetchTimeout bounds one refresh, all its downloads together.
	fetchTimeout = 2 * time.Minute
	// maxFileBytes bounds one download; a list with its signatures is about a megabyte.
	maxFileBytes = 16 << 20
)

// Trust is an environment's trust material, downloaded and kept current (IDPV-007, IDPV-008). Safe for
// concurrent use.
type Trust struct {
	urls          urls
	anchor        []byte
	signerAnchors [][]byte
	// checker asks for the TSL signer's status when the published .ocsp does not answer it.
	checker  tipki.RevocationChecker
	client   *http.Client
	now      func() time.Time
	interval func(failed bool) time.Duration
	source   *titls.TrustSource

	mu        sync.RWMutex
	store     *tipki.TrustStore
	state     *tipki.TSLState
	fetchedAt time.Time
	listHash  string
	list      []byte
	roots     []byte
	lastError error

	publishing sync.Mutex

	stop    chan struct{}
	stopped chan struct{}
	started atomic.Bool
	once    sync.Once
}

// New fetches once, so a host without a route to the material does not start, and keeps refreshing until
// [Trust.Close]. client carries the downloads and the TSL signer's OCSP; redirects are not followed.
func New(env Environment, client *http.Client) (*Trust, error) {
	if client == nil {
		return nil, errors.New("no HTTP client for the trust material")
	}
	urls, err := urlsFor(env)
	if err != nil {
		return nil, err
	}
	anchor, signerAnchors, err := anchorsFor(env)
	if err != nil {
		return nil, err
	}
	checker := tipki.NewOCSPChecker(titls.OCSPTransport(titls.NewHTTPFetcher(client)))
	trust := newTrust(urls, anchor, signerAnchors, checker, client, time.Now, nextFetch)
	ctx, cancel := context.WithTimeout(context.Background(), fetchTimeout)
	defer cancel()
	if err := trust.refresh(ctx); err != nil {
		return nil, fmt.Errorf("fetching trust material: %w", err)
	}
	trust.start()
	return trust, nil
}

func newTrust(urls urls, anchor []byte, signerAnchors [][]byte, checker tipki.RevocationChecker, client *http.Client,
	now func() time.Time, interval func(failed bool) time.Duration,
) *Trust {
	// A redirect could only lead away from the allowlisted host.
	noRedirect := *client
	noRedirect.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Trust{
		urls:          urls,
		anchor:        anchor,
		signerAnchors: signerAnchors,
		checker:       checker,
		client:        &noRedirect,
		now:           now,
		interval:      interval,
		source:        titls.NewTrustSource(nil),
		stop:          make(chan struct{}),
		stopped:       make(chan struct{}),
	}
}

func nextFetch(failed bool) time.Duration {
	if failed {
		return fetchRetry
	}
	// Spread over ten minutes, so a fleet started together does not fetch together.
	return fetchEvery - time.Duration(rand.Int64N(int64(10*time.Minute))) //nolint:gosec // spreads load, nothing depends on it being unpredictable
}

// Current is the copy in memory, or why it does not stand: it never fetches.
func (t *Trust) Current() (*tipki.TrustStore, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	now := t.now()
	if t.store == nil {
		return nil, errors.New("no trust material")
	}
	if age := now.Sub(t.fetchedAt); age >= tipki.MaxBundleAge {
		return nil, errors.Join(fmt.Errorf("trust material is %s old, the limit is %s", age.Round(time.Minute), tipki.MaxBundleAge), t.lastError)
	}
	// The list's own validity may end before the copy's age does.
	if next := t.store.TSL.TSL.NextUpdate; !next.IsZero() && !now.Before(next) {
		return nil, errors.Join(fmt.Errorf("the list's NextUpdate %s has passed", next), t.lastError)
	}
	return t.store, nil
}

// Source is the snapshot a ti TLS configuration verifies against. It holds what [Trust.Current] would
// return, and nothing from the moment the copy no longer stands, so every ti server is refused then
// (TLSV-033) rather than judged by material that is too old.
func (t *Trust) Source() *titls.TrustSource {
	return t.source
}

// Close ends the refreshing. The copy in memory stands until it is too old.
func (t *Trust) Close() {
	t.once.Do(func() { close(t.stop) })
	if t.started.Load() {
		<-t.stopped
	}
}

func (t *Trust) start() {
	t.started.Store(true)
	go t.run()
}

// run refreshes on schedule and also wakes when the copy stops standing, so the source is withdrawn at that
// instant and not only at the next fetch.
func (t *Trust) run() {
	defer close(t.stopped)
	fetching := time.NewTimer(t.interval(false))
	defer fetching.Stop()
	for {
		var expiring *time.Timer
		var expired <-chan time.Time
		if end, ok := t.expiry(); ok && t.source.Store() != nil {
			expiring = time.NewTimer(max(end.Sub(t.now()), 0))
			expired = expiring.C
		}
		select {
		case <-t.stop:
			if expiring != nil {
				expiring.Stop()
			}
			return
		case <-fetching.C:
			ctx, cancel := context.WithTimeout(context.Background(), fetchTimeout)
			err := t.refresh(ctx)
			cancel()
			if err != nil {
				// May be an outage, may be tampering: the old copy stands only until it is too old.
				slog.Error("refreshing the TI trust material", "error", err)
			}
			fetching.Reset(t.interval(err != nil))
		case <-expired:
			t.publish()
		}
		if expiring != nil {
			expiring.Stop()
		}
	}
}

// expiry is when the copy stops standing: its age limit or the list's NextUpdate, whichever comes first.
func (t *Trust) expiry() (time.Time, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.store == nil {
		return time.Time{}, false
	}
	end := t.fetchedAt.Add(tipki.MaxBundleAge)
	if next := t.store.TSL.TSL.NextUpdate; !next.IsZero() && next.Before(end) {
		end = next
	}
	return end, true
}

// publish puts what [Trust.Current] holds into the source. A store already there is not swapped in again,
// since every swap ends the reuse of the verdicts reached with the one before.
func (t *Trust) publish() {
	t.publishing.Lock()
	defer t.publishing.Unlock()
	store, err := t.Current()
	if err != nil {
		store = nil
	}
	if t.source.Store() != store {
		t.source.Swap(store)
	}
}

// refresh replaces the copy only with material that passed everything; on failure the old one stays.
func (t *Trust) refresh(ctx context.Context) error {
	err := t.fetch(ctx)
	if err != nil {
		t.mu.Lock()
		t.lastError = err
		t.mu.Unlock()
	}
	t.publish()
	return err
}

func (t *Trust) fetch(ctx context.Context) error {
	now := t.now()
	hash, err := t.publishedHash(ctx)
	if err != nil {
		return err
	}
	t.mu.RLock()
	list, listHash, state := t.list, t.listHash, t.state
	t.mu.RUnlock()
	if hash != listHash {
		// A_30044: the list is downloaded only when the hash says it changed.
		if list, err = t.get(ctx, t.urls.list+".xml"); err != nil {
			return err
		}
		digest := sha256.Sum256(list)
		if got := hex.EncodeToString(digest[:]); got != hash {
			return fmt.Errorf("the list hashes to %s, %s names %s", got, t.urls.hash, hash)
		}
	}
	signature, err := t.get(ctx, t.urls.list+".sig")
	if err != nil {
		return err
	}
	// Without a current .ocsp the signer's status is asked online, so its absence is not a failure.
	signerStatus, err := t.get(ctx, t.urls.list+".ocsp")
	if err != nil {
		slog.Warn("no .ocsp for the list's signer, asking its responder", "error", err)
		signerStatus = nil
	}
	roots, err := t.get(ctx, t.urls.roots)
	if err != nil {
		return err
	}
	store, err := t.load(ctx, &tipki.Bundle{
		Label:           "fetched",
		AnchorSHA256:    sha256.Sum256(t.anchor),
		Roots:           roots,
		TSL:             list,
		TSLSignature:    signature,
		TSLSignerStatus: signerStatus,
		FetchedAt:       now,
	}, now, state)
	if err != nil {
		return err
	}
	verified := store.TSL.State()
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.store != nil && bytes.Equal(list, t.list) && bytes.Equal(roots, t.roots) && sameTrust(store, t.store) {
		store = t.store
	}
	t.store, t.state, t.fetchedAt, t.list, t.roots, t.listHash, t.lastError = store, &verified, now, list, roots, hash, nil
	return nil
}

// sameTrust says whether two stores loaded from the same list and roots decide alike. What could differ
// between them is what depends on the time of loading: the roots whose links still hold, and the warnings.
func sameTrust(a, b *tipki.TrustStore) bool {
	raw := func(cert *x509.Certificate) []byte { return cert.Raw }
	code := func(warning *tipki.TSLError) string { return warning.Code }
	return slices.EqualFunc(a.Roots, b.Roots, func(x, y *x509.Certificate) bool { return bytes.Equal(raw(x), raw(y)) }) &&
		slices.EqualFunc(a.Intermediates, b.Intermediates, func(x, y tipki.Intermediate) bool {
			return bytes.Equal(raw(x.Certificate), raw(y.Certificate)) && x.Provider == y.Provider && x.RevokedSince.Equal(y.RevokedSince)
		}) &&
		slices.EqualFunc(a.TSL.Warnings, b.TSL.Warnings, func(x, y *tipki.TSLError) bool { return code(x) == code(y) })
}

// load verifies a bundle and settles the signer's status, online if the bundle's does not answer it.
func (t *Trust) load(ctx context.Context, bundle *tipki.Bundle, now time.Time, state *tipki.TSLState) (*tipki.TrustStore, error) {
	store, err := tipki.LoadTrustStore(bundle, t.anchor, t.signerAnchors, now, 0, state)
	if err != nil {
		return nil, err
	}
	unqueried := slices.ContainsFunc(store.TSL.Warnings, func(warning *tipki.TSLError) bool { return warning.Code == "no_ocsp_check" })
	if unqueried {
		if err := store.TSL.CheckSignerStatus(ctx, t.checker); err != nil {
			return nil, err
		}
	}
	return store, nil
}

func (t *Trust) publishedHash(ctx context.Context) (string, error) {
	body, err := t.get(ctx, t.urls.hash)
	if err != nil {
		return "", err
	}
	fields := strings.Fields(string(body))
	if len(fields) == 0 {
		return "", fmt.Errorf("%s: empty", t.urls.hash)
	}
	hash := strings.ToLower(fields[0])
	if digest, err := hex.DecodeString(hash); err != nil || len(digest) != sha256.Size {
		return "", fmt.Errorf("%s: not a SHA-256", t.urls.hash)
	}
	return hash, nil
}

func (t *Trust) get(ctx context.Context, url string) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, err
	}
	response, err := t.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s answered %d", url, response.StatusCode)
	}
	var body bytes.Buffer
	if _, err := io.Copy(&body, io.LimitReader(response.Body, maxFileBytes+1)); err != nil {
		return nil, fmt.Errorf("reading %s: %w", url, err)
	}
	if body.Len() > maxFileBytes {
		return nil, fmt.Errorf("%s: larger than %d bytes", url, maxFileBytes)
	}
	return body.Bytes(), nil
}
