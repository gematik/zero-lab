package gempki

import (
	"crypto/x509"
	"encoding/hex"
	"fmt"
)

// TrustStore is an immutable set of root certificates that gempki trusts
// directly. Intermediate CAs are NOT part of the TrustStore — they arrive
// via the TSL (Phase 3 chain building) or in the candidate chain itself.
//
// TrustStore is safe for concurrent use. Once constructed, its contents
// never change; callers wanting hot-reload semantics use [TrustStoreHolder].
type TrustStore struct {
	all          []*x509.Certificate
	byCommonName map[string]*x509.Certificate
	bySKI        map[string]*x509.Certificate // key: hex(SKI)
}

// NewTrustStore returns an immutable TrustStore over the given roots.
//
// Every root must pass [assertECC] — RSA and other non-TI-PKI key types are
// rejected up-front with [ErrRSANotSupported] (wrapped) so an attacker cannot
// smuggle an unsupported algorithm into the trust store and have it surface
// as a chain-building failure deeper in the validator.
//
// Duplicate roots (same SKI) are deduplicated; the first occurrence wins.
// Conflicting CommonName entries (same CN, different SKI) coexist — only the
// first wins in the CN index, so callers should prefer SKI lookup when
// available.
func NewTrustStore(roots []*x509.Certificate) (*TrustStore, error) {
	ts := &TrustStore{
		byCommonName: make(map[string]*x509.Certificate, len(roots)),
		bySKI:        make(map[string]*x509.Certificate, len(roots)),
		all:          make([]*x509.Certificate, 0, len(roots)),
	}
	for _, r := range roots {
		if r == nil {
			return nil, fmt.Errorf("gempki: nil certificate in trust store input")
		}
		if err := assertECC(r.PublicKey); err != nil {
			return nil, fmt.Errorf("gempki: trust store rejected %q: %w", r.Subject.CommonName, err)
		}
		key := hex.EncodeToString(r.SubjectKeyId)
		if _, exists := ts.bySKI[key]; exists {
			continue // dedupe
		}
		ts.bySKI[key] = r
		if _, exists := ts.byCommonName[r.Subject.CommonName]; !exists {
			ts.byCommonName[r.Subject.CommonName] = r
		}
		ts.all = append(ts.all, r)
	}
	return ts, nil
}

// Roots returns a copy of the trusted root slice. The returned slice may be
// modified by the caller without affecting the TrustStore.
func (ts *TrustStore) Roots() []*x509.Certificate {
	if ts == nil {
		return nil
	}
	out := make([]*x509.Certificate, len(ts.all))
	copy(out, ts.all)
	return out
}

// ByCommonName returns the first root with the given Subject CommonName.
// Returns (nil, false) if no such root exists.
func (ts *TrustStore) ByCommonName(cn string) (*x509.Certificate, bool) {
	if ts == nil {
		return nil, false
	}
	c, ok := ts.byCommonName[cn]
	return c, ok
}

// BySKI returns the root with the given SubjectKeyIdentifier. SKI lookup is
// the preferred match because CommonName is not guaranteed to be unique
// across a rollover.
func (ts *TrustStore) BySKI(ski []byte) (*x509.Certificate, bool) {
	if ts == nil {
		return nil, false
	}
	c, ok := ts.bySKI[hex.EncodeToString(ski)]
	return c, ok
}

// CertPool returns a fresh [x509.CertPool] containing every root in the
// TrustStore. Suitable for `tls.Config.RootCAs`.
//
// Note: this pool does NOT include intermediate CAs. Wiring intermediates
// from the TSL is the responsibility of the Phase 3 chain builder.
func (ts *TrustStore) CertPool() *x509.CertPool {
	pool := x509.NewCertPool()
	if ts == nil {
		return pool
	}
	for _, r := range ts.all {
		pool.AddCert(r)
	}
	return pool
}

// Len returns the number of distinct roots.
func (ts *TrustStore) Len() int {
	if ts == nil {
		return 0
	}
	return len(ts.all)
}
