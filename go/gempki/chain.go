package gempki

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
)

// DefaultMaxChainLen is the upper bound on a built chain's length.
// 5 covers EE → SubCA → SubSubCA → Root rollover scenarios with headroom and
// keeps adversarial chain construction (cyclic links, mega-chains) bounded.
const DefaultMaxChainLen = 5

// BuildChainOptions configures [BuildChain].
type BuildChainOptions struct {
	// MaxChainLen caps the total chain length (EE + intermediates + root).
	// Zero means [DefaultMaxChainLen].
	MaxChainLen int
}

// BuildChain walks issuer references from leaf up through intermediates until
// it lands on a [TrustStore] root. Returns the ordered chain [leaf, mid1, ...,
// root] on success.
//
// Topology only — no signature verification, no time checks. Use [ValidatePath]
// on the returned chain to enforce RFC 5280 §6 semantics. Splitting the two
// makes each easier to reason about and lets callers cache built chains where
// it makes sense.
//
// Lookup preference:
//   - if the cert has an AuthorityKeyIdentifier, match against SubjectKeyIds
//     (precise: works through rollover when two roots share a CommonName);
//   - otherwise fall back to Issuer/Subject DN match.
//
// Errors are wrapped [ErrChainIncomplete] when no candidate matches, or a
// distinct error when MaxChainLen is exceeded or a cycle is detected.
func BuildChain(leaf *x509.Certificate, intermediates []*x509.Certificate, ts *TrustStore, opts BuildChainOptions) ([]*x509.Certificate, error) {
	if leaf == nil {
		return nil, fmt.Errorf("gempki: BuildChain requires a non-nil leaf")
	}
	if ts == nil {
		return nil, fmt.Errorf("gempki: BuildChain requires a non-nil TrustStore")
	}
	maxLen := opts.MaxChainLen
	if maxLen <= 0 {
		maxLen = DefaultMaxChainLen
	}

	chain := []*x509.Certificate{leaf}
	seen := make(map[string]bool, maxLen)
	seen[skiKey(leaf.SubjectKeyId)] = true

	current := leaf
	for len(chain) < maxLen {
		// Self-signed at any non-anchor position is a dead end — the only
		// legitimate self-signed cert in a chain is a TrustStore root, which
		// is handled inside findIssuer below.
		issuer, source, found := findIssuer(current, intermediates, ts)
		if !found {
			return nil, fmt.Errorf("gempki: %w: no issuer for %q (issuer DN %q, AKI %x)",
				ErrChainIncomplete, current.Subject.CommonName, current.Issuer.CommonName, current.AuthorityKeyId)
		}
		if seen[skiKey(issuer.SubjectKeyId)] && source != issuerSourceTrustStore {
			return nil, fmt.Errorf("gempki: %w: cycle detected at %q",
				ErrChainIncomplete, issuer.Subject.CommonName)
		}
		chain = append(chain, issuer)
		if source == issuerSourceTrustStore {
			return chain, nil
		}
		seen[skiKey(issuer.SubjectKeyId)] = true
		current = issuer
	}
	return nil, fmt.Errorf("gempki: %w: chain exceeds MaxChainLen=%d (last subject %q)",
		ErrChainIncomplete, maxLen, current.Subject.CommonName)
}

type issuerSource int

const (
	issuerSourceNone issuerSource = iota
	issuerSourceIntermediate
	issuerSourceTrustStore
)

// findIssuer locates the issuer of c. TrustStore matches are preferred over
// intermediates so a self-signed cert that happens to appear both as the
// leaf's chain partner and in the trust store terminates the walk cleanly.
func findIssuer(c *x509.Certificate, intermediates []*x509.Certificate, ts *TrustStore) (*x509.Certificate, issuerSource, bool) {
	// Trust-store-first lookup.
	if len(c.AuthorityKeyId) > 0 {
		if anchor, ok := ts.BySKI(c.AuthorityKeyId); ok && nameMatches(c.Issuer, anchor.Subject) {
			return anchor, issuerSourceTrustStore, true
		}
	} else if anchor, ok := ts.ByCommonName(c.Issuer.CommonName); ok && nameMatches(c.Issuer, anchor.Subject) {
		return anchor, issuerSourceTrustStore, true
	}

	// Intermediate lookup.
	for _, inter := range intermediates {
		if !nameMatches(c.Issuer, inter.Subject) {
			continue
		}
		if len(c.AuthorityKeyId) > 0 && !bytes.Equal(c.AuthorityKeyId, inter.SubjectKeyId) {
			continue
		}
		return inter, issuerSourceIntermediate, true
	}
	return nil, issuerSourceNone, false
}

// nameMatches compares two pkix.Names by their full RDN sequence rather than
// just CommonName, because intermediate CAs can share a CommonName across
// rollover. Falls back to CommonName when RawSubject/RawIssuer are unset.
func nameMatches(issuer, subject pkix.Name) bool {
	if issuer.String() != "" && subject.String() != "" {
		return issuer.String() == subject.String()
	}
	return issuer.CommonName == subject.CommonName
}

func skiKey(ski []byte) string { return hex.EncodeToString(ski) }
