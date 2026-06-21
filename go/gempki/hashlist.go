package gempki

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// HashListEntry is one record in a revoked-cert hash list.
//
// The hash is over (issuer DN || serial) — see [HashCert] — matching
// [RevocationCacheKey] so cache keys and hash-list keys coincide.
type HashListEntry struct {
	RevokedAt time.Time
	Reason    string
}

// HashListChecker implements [RevocationChecker] against an in-memory set
// of revoked certificate hashes. Suitable as an offline alternative or
// fallback to OCSP for TI use cases that publish a periodic revocation list.
//
// HashListChecker is safe for concurrent reads. Mutation (Add, Remove,
// Replace, LoadFrom) is also safe but blocks readers briefly.
type HashListChecker struct {
	mu      sync.RWMutex
	entries map[string]HashListEntry // key: HashCert(cert)
}

// NewHashListChecker returns an empty HashListChecker. Populate via
// [HashListChecker.Add], [HashListChecker.LoadFrom], or by calling
// [HashListChecker.Replace] with a full snapshot.
func NewHashListChecker() *HashListChecker {
	return &HashListChecker{entries: make(map[string]HashListEntry)}
}

// Add records cert as revoked with the given entry. Useful for tests and
// for callers building the list programmatically.
func (c *HashListChecker) Add(cert *x509.Certificate, entry HashListEntry) {
	c.mu.Lock()
	c.entries[HashCert(cert)] = entry
	c.mu.Unlock()
}

// AddHash records a raw hash key as revoked. Useful when feeding lists in
// gematik's published wire format where only the hash is available.
func (c *HashListChecker) AddHash(hashKey string, entry HashListEntry) {
	c.mu.Lock()
	c.entries[hashKey] = entry
	c.mu.Unlock()
}

// Remove deletes cert's entry. No-op if not present.
func (c *HashListChecker) Remove(cert *x509.Certificate) {
	c.mu.Lock()
	delete(c.entries, HashCert(cert))
	c.mu.Unlock()
}

// Replace atomically swaps the entire entry set. Used after a successful
// reload from a Loader so partially-loaded lists don't go live.
func (c *HashListChecker) Replace(entries map[string]HashListEntry) {
	c.mu.Lock()
	c.entries = entries
	c.mu.Unlock()
}

// Len returns the number of revoked entries currently held.
func (c *HashListChecker) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

// Check implements [RevocationChecker]. Returns Status=Revoked when cert's
// hash is in the list, Status=Good otherwise. The issuer parameter is unused
// — the hash already binds the issuer via the DN — but kept for interface
// uniformity.
//
// HashListChecker never returns Status=Unknown: a hash-list lookup is a
// deterministic offline check. If the list itself is stale, that's a
// freshness problem the caller solves at load time, not here.
func (c *HashListChecker) Check(_ context.Context, cert, _ *x509.Certificate) (*RevocationResult, error) {
	if cert == nil {
		return nil, fmt.Errorf("gempki: HashListChecker.Check requires a non-nil cert")
	}
	c.mu.RLock()
	entry, revoked := c.entries[HashCert(cert)]
	c.mu.RUnlock()

	r := &RevocationResult{
		Source:    RevocationSourceHashList,
		CheckedAt: time.Now(),
	}
	if !revoked {
		r.Status = RevocationStatusGood
		return r, nil
	}
	r.Status = RevocationStatusRevoked
	r.RevokedAt = entry.RevokedAt
	r.Reason = entry.Reason
	return r, nil
}

// LoadFrom parses a simple text format into the checker, replacing the
// current entries on success.
//
// Format (one entry per line, fields separated by whitespace):
//
//	<hex-hash>  <RFC3339-revoked-at>  [reason words...]
//
// Lines starting with "#" and blank lines are ignored. This is intentionally
// minimal — real gematik wire formats can be parsed by callers and fed via
// [HashListChecker.Replace].
func (c *HashListChecker) LoadFrom(r io.Reader) error {
	entries := map[string]HashListEntry{}
	scanner := bufio.NewScanner(r)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return fmt.Errorf("hash list line %d: want at least <hash> <revokedAt>, got %q", lineNo, line)
		}
		if _, err := hex.DecodeString(fields[0]); err != nil {
			return fmt.Errorf("hash list line %d: bad hex: %w", lineNo, err)
		}
		ts, err := time.Parse(time.RFC3339, fields[1])
		if err != nil {
			return fmt.Errorf("hash list line %d: bad timestamp: %w", lineNo, err)
		}
		entry := HashListEntry{RevokedAt: ts}
		if len(fields) > 2 {
			entry.Reason = strings.Join(fields[2:], " ")
		}
		entries[strings.ToLower(fields[0])] = entry
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read hash list: %w", err)
	}
	c.Replace(entries)
	return nil
}

// HashCert returns the canonical key used by the hash list: SHA-256 of
// (RawIssuer || serial). The key is the same as [RevocationCacheKey] so a
// hash-list hit on the EE can backfill the OCSP cache and vice-versa.
func HashCert(cert *x509.Certificate) string {
	h := sha256.New()
	h.Write(cert.RawIssuer)
	h.Write(cert.SerialNumber.Bytes())
	return hex.EncodeToString(h.Sum(nil))
}

// --- Loaders ---------------------------------------------------------------

// HashListLoader sources a HashListChecker. Implementations: [HashListFileLoader],
// [HashListNetworkLoader], [HashListCompositeLoader]. Bytes loaders that wrap
// raw payloads can be built ad-hoc with [HashListChecker.LoadFrom].
//
// The Loader pattern mirrors [Loader] for trust stores so callers can use the
// same compose-network-with-embedded idiom: prefer the live list, fall back
// to a packaged snapshot when offline. See [[feedback-https-client-and-airgap]].
type HashListLoader interface {
	Load(ctx context.Context) (*HashListChecker, error)
}

// HashListFileLoader reads the simple text format from a file on disk.
type HashListFileLoader struct {
	Path string
}

// Load implements [HashListLoader].
func (l HashListFileLoader) Load(_ context.Context) (*HashListChecker, error) {
	f, err := os.Open(l.Path)
	if err != nil {
		return nil, fmt.Errorf("open hash list: %w", err)
	}
	defer f.Close()
	checker := NewHashListChecker()
	if err := checker.LoadFrom(f); err != nil {
		return nil, err
	}
	return checker, nil
}

// HashListNetworkLoader fetches the simple text format over HTTPS, honouring
// HTTPClient + context per the project HTTPS rule.
type HashListNetworkLoader struct {
	URL        string
	HTTPClient *http.Client
}

// Load implements [HashListLoader].
func (l HashListNetworkLoader) Load(ctx context.Context) (*HashListChecker, error) {
	if l.URL == "" {
		return nil, fmt.Errorf("gempki: HashListNetworkLoader requires URL")
	}
	client := l.HTTPClient
	if client == nil {
		client = defaultHTTPClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, l.URL, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("build hash list request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch hash list: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch hash list: HTTP %d from %s", resp.StatusCode, l.URL)
	}
	checker := NewHashListChecker()
	if err := checker.LoadFrom(resp.Body); err != nil {
		return nil, err
	}
	return checker, nil
}

// HashListCompositeLoader tries each loader in order and returns the first
// success. Mirrors [CompositeLoader] for trust stores.
type HashListCompositeLoader struct {
	Loaders []HashListLoader
}

// Load implements [HashListLoader].
func (l HashListCompositeLoader) Load(ctx context.Context) (*HashListChecker, error) {
	if len(l.Loaders) == 0 {
		return nil, fmt.Errorf("gempki: HashListCompositeLoader has no Loaders")
	}
	var lastErr error
	for _, ld := range l.Loaders {
		c, err := ld.Load(ctx)
		if err == nil {
			return c, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("gempki: all hash list loaders failed: %w", lastErr)
}

// --- Reload --------------------------------------------------------------

// HashListHolder is the hash-list counterpart of [TrustStoreHolder]: atomic
// hot-swap of the active checker so a refresh job can keep validators
// pointed at a live list without restart.
type HashListHolder struct {
	ptr atomic.Pointer[HashListChecker]
}

// NewHashListHolder returns a holder seeded with initial (may be nil).
func NewHashListHolder(initial *HashListChecker) *HashListHolder {
	h := &HashListHolder{}
	if initial != nil {
		h.ptr.Store(initial)
	}
	return h
}

// Current returns the active checker, or nil if none has been installed.
func (h *HashListHolder) Current() *HashListChecker {
	if h == nil {
		return nil
	}
	return h.ptr.Load()
}

// Set installs c as the active checker. Refuses nil for the same reason
// [TrustStoreHolder.Set] does.
func (h *HashListHolder) Set(c *HashListChecker) error {
	if h == nil {
		return fmt.Errorf("gempki: HashListHolder is nil")
	}
	if c == nil {
		return fmt.Errorf("gempki: refusing to install nil HashListChecker")
	}
	h.ptr.Store(c)
	return nil
}

// Reload runs loader and installs the result on success; on failure the
// current checker stays in place.
func (h *HashListHolder) Reload(ctx context.Context, loader HashListLoader) error {
	if h == nil {
		return fmt.Errorf("gempki: HashListHolder is nil")
	}
	if loader == nil {
		return fmt.Errorf("gempki: Reload requires a non-nil Loader")
	}
	c, err := loader.Load(ctx)
	if err != nil {
		return err
	}
	return h.Set(c)
}
