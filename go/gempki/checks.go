package gempki

import (
	"context"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// CertificateCheck is a per-certificate predicate executed by
// [ValidatePath]. A non-nil return is recorded as a [ValidationError] in
// the [ValidationResult].
//
// Checks should be cheap and side-effect-free. Long-running work such as
// OCSP belongs in a [RevocationChecker], not here.
type CertificateCheck func(ctx context.Context, cert *x509.Certificate) error

// CheckKeyUsage returns a CertificateCheck that verifies cert.KeyUsage has
// every bit in required set. Bits beyond `required` are not constrained —
// extra usages are permitted.
//
// Returns [*ValidationError] with [ErrCodeKeyUsageMismatch] on failure.
func CheckKeyUsage(required x509.KeyUsage) CertificateCheck {
	return func(_ context.Context, cert *x509.Certificate) error {
		if cert.KeyUsage&required != required {
			return &ValidationError{
				Code:    ErrCodeKeyUsageMismatch,
				Subject: cert.Subject.CommonName,
				Message: fmt.Sprintf("required KeyUsage %s missing (have %s)",
					describeKeyUsage(required), describeKeyUsage(cert.KeyUsage)),
			}
		}
		return nil
	}
}

// CheckHasAnyExtKeyUsage returns a CertificateCheck that verifies
// cert.ExtKeyUsage intersects allowed (at least one entry in common). Use
// when any of several EKUs is acceptable for a given profile.
//
// Returns [*ValidationError] with [ErrCodeKeyUsageMismatch] on failure.
func CheckHasAnyExtKeyUsage(allowed ...x509.ExtKeyUsage) CertificateCheck {
	return func(_ context.Context, cert *x509.Certificate) error {
		if hasExtKeyUsage(cert, x509.ExtKeyUsageAny) {
			return nil
		}
		for _, want := range allowed {
			if hasExtKeyUsage(cert, want) {
				return nil
			}
		}
		names := make([]string, len(allowed))
		for i, eku := range allowed {
			names[i] = describeExtKeyUsage(eku)
		}
		return &ValidationError{
			Code:    ErrCodeKeyUsageMismatch,
			Subject: cert.Subject.CommonName,
			Message: fmt.Sprintf("certificate ExtKeyUsage matches none of: %s", strings.Join(names, ", ")),
		}
	}
}

func hasExtKeyUsage(cert *x509.Certificate, want x509.ExtKeyUsage) bool {
	return slices.Contains(cert.ExtKeyUsage, want)
}

// describeKeyUsage renders a KeyUsage bitmask as a human-readable list of
// the bits that are set. Used in error messages so failures self-explain.
func describeKeyUsage(ku x509.KeyUsage) string {
	names := []string{}
	if ku&x509.KeyUsageDigitalSignature != 0 {
		names = append(names, "digitalSignature")
	}
	if ku&x509.KeyUsageContentCommitment != 0 {
		names = append(names, "contentCommitment")
	}
	if ku&x509.KeyUsageKeyEncipherment != 0 {
		names = append(names, "keyEncipherment")
	}
	if ku&x509.KeyUsageDataEncipherment != 0 {
		names = append(names, "dataEncipherment")
	}
	if ku&x509.KeyUsageKeyAgreement != 0 {
		names = append(names, "keyAgreement")
	}
	if ku&x509.KeyUsageCertSign != 0 {
		names = append(names, "keyCertSign")
	}
	if ku&x509.KeyUsageCRLSign != 0 {
		names = append(names, "cRLSign")
	}
	if ku&x509.KeyUsageEncipherOnly != 0 {
		names = append(names, "encipherOnly")
	}
	if ku&x509.KeyUsageDecipherOnly != 0 {
		names = append(names, "decipherOnly")
	}
	if len(names) == 0 {
		return "(none)"
	}
	return strings.Join(names, "|")
}

func describeExtKeyUsage(eku x509.ExtKeyUsage) string {
	switch eku {
	case x509.ExtKeyUsageAny:
		return "any"
	case x509.ExtKeyUsageServerAuth:
		return "id-kp-serverAuth"
	case x509.ExtKeyUsageClientAuth:
		return "id-kp-clientAuth"
	case x509.ExtKeyUsageCodeSigning:
		return "id-kp-codeSigning"
	case x509.ExtKeyUsageEmailProtection:
		return "id-kp-emailProtection"
	case x509.ExtKeyUsageOCSPSigning:
		return "id-kp-OCSPSigning"
	case x509.ExtKeyUsageTimeStamping:
		return "id-kp-timeStamping"
	default:
		return fmt.Sprintf("ExtKeyUsage(%d)", eku)
	}
}

// CheckCertificatePolicies returns a [CertificateCheck] that requires
// cert.PolicyIdentifiers to contain every OID in required.
//
// Empty required → no constraint (check always passes).
//
// The TI profiles for QES, ZETA, IDP, and Komponenten all assert
// [OIDPolicyGemOrCP] (1.2.276.0.76.4.163), and the QES profile additionally
// asserts [OIDPolicyHbaCP]. Use this check to fail closed when those
// policies are absent.
func CheckCertificatePolicies(required ...asn1.ObjectIdentifier) CertificateCheck {
	return func(_ context.Context, cert *x509.Certificate) error {
		if len(required) == 0 {
			return nil
		}
		missing := make([]asn1.ObjectIdentifier, 0)
		for _, want := range required {
			if !hasPolicyIdentifier(cert, want) {
				missing = append(missing, want)
			}
		}
		if len(missing) == 0 {
			return nil
		}
		return &ValidationError{
			Code:    ErrCodePolicyMismatch,
			Subject: cert.Subject.CommonName,
			Message: fmt.Sprintf("required CertificatePolicy missing: %s (have %s)",
				oidsToString(missing), oidsToString(cert.PolicyIdentifiers)),
		}
	}
}

func hasPolicyIdentifier(cert *x509.Certificate, want asn1.ObjectIdentifier) bool {
	for _, have := range cert.PolicyIdentifiers {
		if have.Equal(want) {
			return true
		}
	}
	return false
}

// roleOIDs returns the profession OIDs the certificate asserts in its
// admission extension. A certificate without the extension asserts none —
// that is an empty slice, not an error, so the caller's policy decides
// whether "no roles" is acceptable.
func roleOIDs(cert *x509.Certificate) ([]asn1.ObjectIdentifier, error) {
	stmt, err := ParseAdmissionStatement(cert)
	if errors.Is(err, ErrNoAdmissionStatement) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("gempki: extract role OIDs: %w", err)
	}
	out := make([]asn1.ObjectIdentifier, 0, len(stmt.ProfessionOids))
	for _, s := range stmt.ProfessionOids {
		oid, err := parseDottedOID(s)
		if err != nil {
			return nil, fmt.Errorf("gempki: parse profession OID %q: %w", s, err)
		}
		out = append(out, oid)
	}
	return out, nil
}

// CheckRoleOID returns a [CertificateCheck] requiring the certificate's
// admission roles to intersect allowed. An empty allowed list means no
// constraint. On failure the error carries [ErrCodeRoleOIDMissing] and lists
// what the certificate asserted against what was required.
func CheckRoleOID(allowed ...asn1.ObjectIdentifier) CertificateCheck {
	return func(_ context.Context, cert *x509.Certificate) error {
		if len(allowed) == 0 {
			return nil
		}
		have, err := roleOIDs(cert)
		if err != nil {
			return &ValidationError{
				Code:    ErrCodeRoleOIDMissing,
				Subject: cert.Subject.CommonName,
				Message: "role OID extraction failed",
				Cause:   err,
			}
		}
		if oidsIntersect(have, allowed) {
			return nil
		}
		return &ValidationError{
			Code:    ErrCodeRoleOIDMissing,
			Subject: cert.Subject.CommonName,
			Message: fmt.Sprintf("required role OID missing: have %s, want one of %s",
				oidsToString(have), oidsToString(allowed)),
		}
	}
}

func oidsIntersect(a, b []asn1.ObjectIdentifier) bool {
	for _, x := range a {
		if slices.ContainsFunc(b, x.Equal) {
			return true
		}
	}
	return false
}

func oidsToString(oids []asn1.ObjectIdentifier) string {
	if len(oids) == 0 {
		return "(none)"
	}
	parts := make([]string, len(oids))
	for i, o := range oids {
		parts[i] = o.String()
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

// parseDottedOID parses "1.2.276.0.76.4.30" → [asn1.ObjectIdentifier].
// asn1 has no public parser for the dotted form, so we walk it ourselves —
// faster than going through asn1.Marshal/Unmarshal.
func parseDottedOID(s string) (asn1.ObjectIdentifier, error) {
	if s == "" {
		return nil, fmt.Errorf("empty OID")
	}
	parts := strings.Split(s, ".")
	out := make(asn1.ObjectIdentifier, 0, len(parts))
	for _, p := range parts {
		n := 0
		if p == "" {
			return nil, fmt.Errorf("empty arc in %q", s)
		}
		for _, c := range p {
			if c < '0' || c > '9' {
				return nil, fmt.Errorf("non-digit %q in %q", c, s)
			}
			n = n*10 + int(c-'0')
		}
		out = append(out, n)
	}
	return out, nil
}
