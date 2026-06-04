package gempki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/asn1"
	"fmt"

	"github.com/gematik/zero-lab/go/brainpool"
)

// Curve OIDs supported by the TI-PKI.
//
// The Brainpool OIDs come from RFC 5639 §4.1; the NIST OIDs from RFC 5480 §2.1.1.1.
// These are mirrored in oids.go for caller convenience; the duplicates here keep
// the brainpool / parse layer self-contained.
var (
	OIDBrainpoolP256r1 = asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 8, 1, 1, 7}
	OIDBrainpoolP384r1 = asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 8, 1, 1, 11}
	OIDNISTP256        = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	OIDNISTP384        = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
)

// BrainpoolP256r1 returns the Brainpool P-256r1 curve (RFC 5639 §3.4).
// It delegates to the sibling brainpool package, which has the curve math.
func BrainpoolP256r1() elliptic.Curve { return brainpool.P256r1() }

// BrainpoolP384r1 returns the Brainpool P-384r1 curve (RFC 5639 §3.6).
func BrainpoolP384r1() elliptic.Curve { return brainpool.P384r1() }

// CurveForOID returns the [elliptic.Curve] for a supported named-curve OID.
// Supported curves are NIST P-256, NIST P-384, Brainpool P256r1, and Brainpool P384r1.
// Unknown or unsupported OIDs (including secp256k1, P-521, Brainpool P512r1) return an error —
// the TI-PKI does not use them per gemSpec_Krypt.
func CurveForOID(oid asn1.ObjectIdentifier) (elliptic.Curve, error) {
	switch {
	case oid.Equal(OIDNISTP256):
		return elliptic.P256(), nil
	case oid.Equal(OIDNISTP384):
		return elliptic.P384(), nil
	case oid.Equal(OIDBrainpoolP256r1):
		return brainpool.P256r1(), nil
	case oid.Equal(OIDBrainpoolP384r1):
		return brainpool.P384r1(), nil
	}
	return nil, fmt.Errorf("gempki: unsupported elliptic curve OID %s", oid)
}

// assertECC verifies that pub is an ECDSA public key on a curve allowed by
// the TI-PKI. Any other key type (RSA, Ed25519, unknown) is rejected with a
// loud, attributable error. This is the single crypto-policy gate the rest of
// the package relies on; every entrypoint that observes a public key must
// route through here.
func assertECC(pub crypto.PublicKey) error {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		if k == nil || k.Curve == nil {
			return fmt.Errorf("gempki: nil ECDSA public key")
		}
		return assertCurveAllowed(k.Curve)
	case *rsa.PublicKey:
		return ErrRSANotSupported
	case ed25519.PublicKey:
		return fmt.Errorf("gempki: Ed25519 is not supported in the TI-PKI")
	default:
		return fmt.Errorf("gempki: unsupported public key type %T", pub)
	}
}

// assertCurveAllowed rejects ECDSA keys on curves outside the TI-PKI policy
// (e.g. secp256k1, NIST P-521, Brainpool P512r1).
func assertCurveAllowed(curve elliptic.Curve) error {
	switch curve {
	case elliptic.P256(), elliptic.P384():
		return nil
	case brainpool.P256r1(), brainpool.P384r1():
		return nil
	}
	name := "unnamed"
	if p := curve.Params(); p != nil && p.Name != "" {
		name = p.Name
	}
	return fmt.Errorf("gempki: unsupported elliptic curve %q (TI-PKI allows NIST P-256/P-384 and Brainpool P256r1/P384r1)", name)
}
