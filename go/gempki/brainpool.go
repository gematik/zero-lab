package gempki

import (
	"crypto/elliptic"
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

