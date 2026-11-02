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

package gemidp

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
	"strings"
	"sync"
	"time"

	"github.com/gematik/zero-lab/go/tipki"
)

const (
	// fetchEvery is the usual time between refreshes: the signer's .ocsp is renewed hourly.
	fetchEvery = time.Hour
	// fetchRetry is the time to the next attempt after one failed.
	fetchRetry = 5 * time.Minute
	// fetchTimeout bounds one refresh, all its downloads together.
	fetchTimeout = 2 * time.Minute
)

// trustURLs are where an environment publishes its trust material. These are fixed, as outbound fetches go only
// to allowlisted hosts (servers.md rule 2).
type trustURLs struct {
	// roots is roots.json, and hash the list's SHA-256, both over HTTPS (A_30044).
	roots, hash string
	// list is the stem of the automated download point of gemSpec_TSL A_21182: .xml, .sig and .ocsp, over
	// plain HTTP as A_21175 mandates. The signature and the hash make it safe.
	list string
}

func urlsFor(env Environment) (trustURLs, error) {
	switch env {
	case EnvironmentProduction:
		return trustURLs{
			roots: "https://download.tsl.ti-dienste.de/ECC/ROOT-CA/roots.json",
			hash:  "https://download.tsl.ti-dienste.de/ECC/ECC-RSA_TSL.sha2",
			list:  "http://download.crl.ti-dienste.de/TSL-ECC/ECC-RSA_TSL",
		}, nil
	case EnvironmentReference:
		return trustURLs{
			roots: "https://download-ref.tsl.ti-dienste.de/ECC/ROOT-CA/roots.json",
			hash:  "https://download-ref.tsl.ti-dienste.de/ECC/ECC-RSA_TSL-ref.sha2",
			list:  "http://download-testref.crl.ti-dienste.de/TSL-ECC-ref/ECC-RSA_TSL-ref",
		}, nil
	case EnvironmentTest:
		return trustURLs{
			roots: "https://download-test.tsl.ti-dienste.de/ECC/ROOT-CA/roots.json",
			hash:  "https://download-test.tsl.ti-dienste.de/ECC/ECC-RSA_TSL-test.sha2",
			list:  "http://download-testref.crl.ti-dienste.de/TSL-ECC-test/ECC-RSA_TSL-test",
		}, nil
	default:
		return trustURLs{}, errors.New("no IDP-Dienst environment: name test, ref or prod")
	}
}

// FetchingTrust downloads its trust material, for a deployment that has no producer to mount a bundle from
// (decision-12). Nothing it downloads is trusted for where it came from: it passes the checks a bundle passes.
//
// The signature over plain HTTP cannot say a list is the newest, and the memory of the newest one seen ends with
// the process. So a list is taken only under the hash the HTTPS host names (IDPV-007).
//
// It fetches at the start, which must succeed, and then in the background: a login only reads the copy in
// memory, which stands for [tipki.MaxBundleAge] from its last good refresh, and after that refuses (IDPV-008).
type FetchingTrust struct {
	verifier
	urls     trustURLs
	client   *http.Client
	interval func(failed bool) time.Duration

	mu        sync.RWMutex
	store     *tipki.TrustStore
	state     *tipki.TSLState
	fetchedAt time.Time
	listHash  string
	list      []byte
	lastError error

	stop    chan struct{}
	stopped chan struct{}
	once    sync.Once
}

// NewFetchingTrust fetches once, so a deployment without a route to the material does not start, and keeps
// refreshing until [FetchingTrust.Close]. httpClient carries the downloads and OCSP.
func NewFetchingTrust(env Environment, httpClient *http.Client) (*FetchingTrust, error) {
	urls, err := urlsFor(env)
	if err != nil {
		return nil, err
	}
	base, err := newVerifier(env, httpClient)
	if err != nil {
		return nil, err
	}
	trust := newFetchingTrust(base, urls, httpClient)
	if err := trust.refresh(context.Background()); err != nil {
		return nil, fmt.Errorf("fetching trust material: %w", err)
	}
	trust.start()
	return trust, nil
}

func newFetchingTrust(base verifier, urls trustURLs, httpClient *http.Client) *FetchingTrust {
	// A redirect could only lead away from the allowlisted host.
	noRedirect := *httpClient
	noRedirect.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &FetchingTrust{
		verifier: base,
		urls:     urls,
		client:   &noRedirect,
		interval: nextFetch,
		stop:     make(chan struct{}),
		stopped:  make(chan struct{}),
	}
}

func nextFetch(failed bool) time.Duration {
	if failed {
		return fetchRetry
	}
	// Spread over ten minutes, so a fleet started together does not fetch together.
	return fetchEvery - time.Duration(rand.Int64N(int64(10*time.Minute))) //nolint:gosec // spreads load, nothing depends on it being unpredictable
}

func (t *FetchingTrust) start() {
	go func() {
		defer close(t.stopped)
		failed := false
		for {
			timer := time.NewTimer(t.interval(failed))
			select {
			case <-t.stop:
				timer.Stop()
				return
			case <-timer.C:
			}
			ctx, cancel := context.WithTimeout(context.Background(), fetchTimeout)
			err := t.refresh(ctx)
			cancel()
			failed = err != nil
			if failed {
				// May be an outage, may be tampering: the old copy stands only until it is too old.
				slog.Error("refreshing the IDP-Dienst's trust material", "error", err)
			}
		}
	}()
}

// Close ends the refreshing. The copy in memory stands until it is too old.
func (t *FetchingTrust) Close() {
	t.once.Do(func() { close(t.stop) })
	<-t.stopped
}

// Check implements [CertificateTrust]. It never fetches.
func (t *FetchingTrust) Check(ctx context.Context, which IDPCertificate, certs []*x509.Certificate) error {
	if len(certs) == 0 {
		return fmt.Errorf("%s: no certificate", which)
	}
	store, err := t.current()
	if err != nil {
		return fmt.Errorf("%s: %w", which, err)
	}
	return t.check(ctx, store, which, certs)
}

func (t *FetchingTrust) current() (*tipki.TrustStore, error) {
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

// refresh replaces the copy only with material that passed everything; on failure the old one stays.
func (t *FetchingTrust) refresh(ctx context.Context) error {
	err := t.fetch(ctx)
	if err != nil {
		t.mu.Lock()
		t.lastError = err
		t.mu.Unlock()
	}
	return err
}

func (t *FetchingTrust) fetch(ctx context.Context) error {
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
	t.store, t.state, t.fetchedAt, t.list, t.listHash, t.lastError = store, &verified, now, list, hash, nil
	return nil
}

func (t *FetchingTrust) publishedHash(ctx context.Context) (string, error) {
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

func (t *FetchingTrust) get(ctx context.Context, url string) ([]byte, error) {
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
	if _, err := io.Copy(&body, io.LimitReader(response.Body, maxBundleBytes+1)); err != nil {
		return nil, fmt.Errorf("reading %s: %w", url, err)
	}
	if body.Len() > maxBundleBytes {
		return nil, fmt.Errorf("%s: larger than %d bytes", url, maxBundleBytes)
	}
	return body.Bytes(), nil
}
