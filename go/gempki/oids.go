package gempki

import "encoding/asn1"

// OID constants used by gempki.
//
// Curve OIDs (OIDBrainpoolP256r1, OIDBrainpoolP384r1, OIDNISTP256,
// OIDNISTP384) are declared in brainpool.go so the brainpool/parse layer is
// self-contained — they are referenced from this file too via the package
// identifier.

// OIDAdmissionExtension is the X.509v3 extension OID carrying gematik-specific
// profession info on SMC-B and HBA cards. See ISIS-MTT Part 1 §3.1 and
// gemSpec_OID Tab_PKI_310.
//
// Note: the legacy string form lives in admission_statement.go as
// [OIDAdmissionStatement]; the typed form here is what new code should use.
var OIDAdmissionExtension = asn1.ObjectIdentifier{1, 3, 36, 8, 3, 3}

// ECDSA signature algorithm OIDs (RFC 5758 §3.2).
// The TI-PKI uses these exclusively — RSA-with-SHA-* signature OIDs are
// intentionally absent.
var (
	OIDECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	OIDECDSAWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
)

// SMC-B institution profession OIDs (gemSpec_OID).
//
// These appear in the Admission extension of SMC-B end-entity certificates
// and identify the type of healthcare institution. Verified against real TI
// TEST-ONLY certificates in admission_statement_test.go.
//
// This set is intentionally minimal — the full mapping (HBA person OIDs,
// other SMC-B institution OIDs) arrives in Phase 5 (roleoid.go) where it is
// actually consumed by the role-matching logic.
var (
	OIDInstArztpraxis      = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 50}
	OIDInstOeffentlicheApo = asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 54}
)
