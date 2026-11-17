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

package bundlefile

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/gematik/zero-lab/go/tipki"
	"github.com/gematik/zero-lab/go/tipki/titls"
)

const (
	// maxBundleBytes bounds the file as read and, if it is gzipped, as decompressed; a bundle is about 800 kB.
	maxBundleBytes = 16 << 20
	// readTimeout bounds one background read, the signer's responder included.
	readTimeout = 2 * time.Minute
)

var gzipMagic = []byte{0x1f, 0x8b}

// Config is what the host decides: where the file is mounted, what the environment trusts, and when to look.
type Config struct {
	// Path is the bundle file `ti pki trust export` writes, plain or gzipped.
	Path string
	// Anchor is the DER root the walk of roots.json starts from, and SignerAnchors the TSL signer's CAs. The
	// host picks both for its environment: with TEST-ONLY anchors in every build, a default would be trust
	// nobody chose.
	Anchor        []byte
	SignerAnchors [][]byte
	// Checker asks the TSL signer's responder when the bundle holds no current status for the signer. Without
	// one, such a bundle is refused.
	Checker tipki.RevocationChecker
	// Interval is the time between two reads of Path in the background. Zero reads it only on [Trust.Reload].
	Interval time.Duration
	// Logger receives the background reads that failed and the bundles that replaced the one in use.
	Logger *slog.Logger
	// Clock is the time bundles are judged at. When nil, the system clock.
	Clock func() time.Time
}

// Trust is the material of a mounted bundle file, kept current. Safe for concurrent use.
type Trust struct {
	path          string
	anchor        []byte
	signerAnchors [][]byte
	checker       tipki.RevocationChecker
	interval      time.Duration
	logger        *slog.Logger
	now           func() time.Time
	source        *titls.TrustSource

	mu        sync.RWMutex
	store     *tipki.TrustStore
	state     *tipki.TSLState
	fetchedAt time.Time
	digest    [sha256.Size]byte
	lastError error

	// reloading keeps two reads from verifying at once and the slower one from replacing the newer result.
	reloading  sync.Mutex
	publishing sync.Mutex

	cancel  context.CancelFunc
	stopped chan struct{}
}

// New loads the bundle at once, so a deployment without usable trust material does not start, and then
// watches it until [Trust.Close].
func New(ctx context.Context, config Config) (*Trust, error) {
	if config.Path == "" {
		return nil, errors.New("bundlefile: no path")
	}
	if len(config.Anchor) == 0 || len(config.SignerAnchors) == 0 {
		return nil, errors.New("bundlefile: no anchor or no signer anchors")
	}
	if config.Interval < 0 {
		return nil, errors.New("bundlefile: interval is negative")
	}
	logger := config.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	now := config.Clock
	if now == nil {
		now = time.Now
	}
	t := &Trust{
		path:          config.Path,
		anchor:        config.Anchor,
		signerAnchors: config.SignerAnchors,
		checker:       config.Checker,
		interval:      config.Interval,
		logger:        logger,
		now:           now,
		source:        titls.NewTrustSource(nil),
		stopped:       make(chan struct{}),
	}
	if err := t.Reload(ctx); err != nil {
		return nil, err
	}
	// The background reads outlive the caller's deadline and end with Close.
	background, cancel := context.WithCancel(context.WithoutCancel(ctx))
	t.cancel = cancel
	go t.run(background)
	return t, nil
}

// Current is the store in use, or why there is none that stands. It never reads the file.
func (t *Trust) Current() (*tipki.TrustStore, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.store == nil {
		return nil, errors.Join(errors.New("bundlefile: no trust bundle loaded"), t.lastError)
	}
	now := t.now()
	if age := now.Sub(t.fetchedAt); age >= tipki.MaxBundleAge {
		return nil, errors.Join(fmt.Errorf("bundlefile: the bundle in use is %s old, the limit is %s", age.Round(time.Minute), tipki.MaxBundleAge), t.lastError)
	}
	// The list's own validity may end before the bundle's age does.
	if next := t.store.TSL.TSL.NextUpdate; !next.IsZero() && !now.Before(next) {
		return nil, errors.Join(fmt.Errorf("bundlefile: the list's NextUpdate %s has passed", next), t.lastError)
	}
	return t.store, nil
}

// Source is the snapshot a ti TLS configuration verifies against. It holds what [Trust.Current] would return,
// and nothing from the moment that no longer stands (TLSV-033).
func (t *Trust) Source() *titls.TrustSource {
	return t.source
}

// Reload reads the file now. On an error the store in use stays, until it is too old.
func (t *Trust) Reload(ctx context.Context) error {
	t.reloading.Lock()
	defer t.reloading.Unlock()
	err := t.read(ctx)
	t.mu.Lock()
	t.lastError = err
	t.mu.Unlock()
	t.publish()
	return err
}

// Close ends the background reads. The store in use stands until it is too old.
func (t *Trust) Close() {
	t.cancel()
	<-t.stopped
}

// run reads on schedule and also wakes when the store in use stops standing, so the source is withdrawn at
// that instant and not only at the next read.
func (t *Trust) run(ctx context.Context) {
	defer close(t.stopped)
	var ticks <-chan time.Time
	if t.interval > 0 {
		ticker := time.NewTicker(t.interval)
		defer ticker.Stop()
		ticks = ticker.C
	}
	for {
		var expiring *time.Timer
		var expired <-chan time.Time
		if end, ok := t.expiry(); ok && t.source.Store() != nil {
			expiring = time.NewTimer(max(end.Sub(t.now()), 0))
			expired = expiring.C
		}
		select {
		case <-ctx.Done():
			if expiring != nil {
				expiring.Stop()
			}
			return
		case <-ticks:
			readCtx, cancel := context.WithTimeout(ctx, readTimeout)
			err := t.Reload(readCtx)
			cancel()
			if err != nil && ctx.Err() == nil {
				// May be a producer that failed, may be tampering: the store in use stands only until it is too old.
				t.logger.Error("trust bundle not loaded, the one in use stays", "path", t.path, "error", err)
			}
		case <-expired:
			t.publish()
		}
		if expiring != nil {
			expiring.Stop()
		}
	}
}

// expiry is when the store in use stops standing: its age limit or the list's NextUpdate, whichever comes first.
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

// read replaces the store in use only with a bundle that passed everything.
func (t *Trust) read(ctx context.Context) error {
	now := t.now()
	raw, err := readBounded(t.path)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(raw)
	t.mu.RLock()
	loaded, state, fetchedAt, same := t.store != nil, t.state, t.fetchedAt, t.store != nil && digest == t.digest
	t.mu.RUnlock()
	if same {
		return nil
	}
	data, err := decode(raw)
	if err != nil {
		return fmt.Errorf("bundlefile: %w", err)
	}
	bundle, err := tipki.ParseBundle(data)
	if err != nil {
		return err
	}
	// A copy of an older export verifies as well as the newer one did, and would only shorten the time left.
	if loaded && bundle.FetchedAt.Before(fetchedAt) {
		return errors.New("bundlefile: fetched_at is before that of the bundle in use")
	}
	store, err := t.load(ctx, bundle, now, state)
	if err != nil {
		return err
	}
	verified := store.TSL.State()
	t.mu.Lock()
	t.store, t.state, t.fetchedAt, t.digest = store, &verified, bundle.FetchedAt, digest
	t.mu.Unlock()
	t.logger.Info("trust bundle loaded", "path", t.path, "tsl_sequence", verified.SequenceNumber, "fetched_at", bundle.FetchedAt)
	return nil
}

// load verifies a bundle and settles the signer's status, online if the bundle's does not answer it.
func (t *Trust) load(ctx context.Context, bundle *tipki.Bundle, now time.Time, state *tipki.TSLState) (*tipki.TrustStore, error) {
	store, err := tipki.LoadTrustStore(bundle, t.anchor, t.signerAnchors, now, 0, state)
	if err != nil {
		return nil, err
	}
	unqueried := slices.ContainsFunc(store.TSL.Warnings, func(warning *tipki.TSLError) bool { return warning.Code == "no_ocsp_check" })
	if unqueried {
		if t.checker == nil {
			return nil, errors.New("bundlefile: the bundle holds no current tsl_ocsp and no responder may be asked")
		}
		if err := store.TSL.CheckSignerStatus(ctx, t.checker); err != nil {
			return nil, err
		}
	}
	return store, nil
}

// readBounded reads through the path every time, so a repointed symlink is followed.
func readBounded(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("bundlefile: %w", err)
	}
	defer func() { _ = file.Close() }()
	data, err := io.ReadAll(io.LimitReader(file, maxBundleBytes+1))
	if err != nil {
		return nil, fmt.Errorf("bundlefile: %w", err)
	}
	if len(data) > maxBundleBytes {
		return nil, fmt.Errorf("bundlefile: the file is larger than %d bytes", maxBundleBytes)
	}
	return data, nil
}

// decode returns a plain bundle as it is and decompresses a gzipped one, refusing it once it would exceed
// maxBundleBytes, so a small file cannot make the reader allocate without bound.
func decode(raw []byte) ([]byte, error) {
	if !bytes.HasPrefix(raw, gzipMagic) {
		return raw, nil
	}
	compressed := bytes.NewReader(raw)
	reader, err := gzip.NewReader(compressed)
	if err != nil {
		return nil, fmt.Errorf("gzip: %w", err)
	}
	// One member, so that one file has one meaning; a bytes.Reader is read no further than the member ends.
	reader.Multistream(false)
	data, err := io.ReadAll(io.LimitReader(reader, maxBundleBytes+1))
	if err != nil {
		return nil, fmt.Errorf("gzip: %w", err)
	}
	if len(data) > maxBundleBytes {
		return nil, fmt.Errorf("gzip: decompresses to more than %d bytes", maxBundleBytes)
	}
	if compressed.Len() != 0 {
		return nil, errors.New("gzip: data after the gzip member")
	}
	return data, nil
}
