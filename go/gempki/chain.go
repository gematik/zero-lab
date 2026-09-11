package gempki

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
)

// maxChainLen bounds a built chain. 5 covers EE → SubCA → SubSubCA → Root
// rollover scenarios with headroom and keeps adversarial construction
// (cyclic links, mega-chains) bounded.
const maxChainLen = 5

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
// When no candidate matches, the chain exceeds the length bound, or a cycle
// is detected, the error is a [*ValidationError] with [ErrCodeChainIncomplete]
// (errors.Is(err, [ErrChainIncomplete]) holds) and the returned slice is the
// partial chain walked so far, leaf first and ending at the certificate whose
// issuer could not be found — what a caller needs to show where the walk
// stopped. Only a nil leaf or trust store yields a nil slice.
func BuildChain(leaf *x509.Certificate, intermediates []*x509.Certificate, ts *TrustStore) ([]*x509.Certificate, error) {
	if leaf == nil {
		return nil, fmt.Errorf("gempki: BuildChain requires a non-nil leaf")
	}
	if ts == nil {
		return nil, fmt.Errorf("gempki: BuildChain requires a non-nil TrustStore")
	}
	chain := []*x509.Certificate{leaf}
	seen := make(map[string]bool, maxChainLen)
	seen[skiKey(leaf.SubjectKeyId)] = true

	current := leaf
	for len(chain) < maxChainLen {
		// Self-signed at any non-anchor position is a dead end — the only
		// legitimate self-signed cert in a chain is a TrustStore root, which
		// is handled inside findIssuer below.
		issuer, source, found := findIssuer(current, intermediates, ts)
		if !found {
			return chain, &ValidationError{
				Code:    ErrCodeChainIncomplete,
				Subject: current.Subject.CommonName,
				Message: fmt.Sprintf("no issuer found (issuer DN %q, AKI %x)", current.Issuer.CommonName, current.AuthorityKeyId),
			}
		}
		if seen[skiKey(issuer.SubjectKeyId)] && source != issuerSourceTrustStore {
			return chain, &ValidationError{Code: ErrCodeChainIncomplete, Subject: issuer.Subject.CommonName, Message: "cycle detected"}
		}
		chain = append(chain, issuer)
		if source == issuerSourceTrustStore {
			return chain, nil
		}
		seen[skiKey(issuer.SubjectKeyId)] = true
		current = issuer
	}
	return chain, &ValidationError{
		Code:    ErrCodeChainIncomplete,
		Subject: current.Subject.CommonName,
		Message: fmt.Sprintf("chain exceeds %d certificates", maxChainLen),
	}
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

// verifyCertificateSignature checks that child was signed by parent's private key.
//
// Both public keys must be one of the TI-PKI's allowed types (ECDSA on an
// allowed curve, or RSA). The signature itself is verified via the standard
// library, which handles ECDSA (including Brainpool) and RSA / RSA-PSS
// uniformly through [x509.Certificate.CheckSignatureFrom].
func verifyCertificateSignature(child, parent *x509.Certificate) error {
	if child == nil {
		return fmt.Errorf("gempki: nil child certificate")
	}
	if parent == nil {
		return fmt.Errorf("gempki: nil parent certificate")
	}
	if err := child.CheckSignatureFrom(parent); err != nil {
		return fmt.Errorf("gempki: signature verification failed for %q (issuer %q): %w",
			child.Subject.CommonName, parent.Subject.CommonName, err)
	}
	return nil
}
