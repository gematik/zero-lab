package gempki

import (
	"context"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"slices"
	"strings"
)

// RoleOIDExtractorFunc extracts the profession / role OIDs asserted by a
// certificate. The default implementation reads the gematik Admission
// extension (OID 1.3.36.8.3.3); callers can swap in a custom extractor for
// certs that carry roles elsewhere (legacy certs, non-standard policies).
type RoleOIDExtractorFunc func(cert *x509.Certificate) ([]asn1.ObjectIdentifier, error)

// DefaultRoleOIDExtractor reads the Admission extension and returns the
// professionOIDs as a slice of [asn1.ObjectIdentifier].
//
// Returns an empty slice (and no error) when the Admission extension is
// absent — the caller's check (typically [CheckRoleOID]) is responsible for
// deciding whether that's acceptable. This split exists so an EE without
// role assertions can be allowed when a profile doesn't constrain roles, but
// rejected loudly when it does.
//
// Wraps [ParseAdmissionStatement] (existing parser); the string-form OIDs
// from that API are converted to typed [asn1.ObjectIdentifier].
func DefaultRoleOIDExtractor(cert *x509.Certificate) ([]asn1.ObjectIdentifier, error) {
	stmt, err := ParseAdmissionStatement(cert)
	if err != nil {
		// "extension not found" is the common case; return empty rather than
		// surfacing it as an error so the caller's policy decides.
		if strings.Contains(err.Error(), "admission statement extension not found") {
			return nil, nil
		}
		return nil, fmt.Errorf("gempki: extract role OIDs: %w", err)
	}
	if stmt == nil {
		return nil, nil
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

// CheckRoleOID returns a [CertificateCheck] that requires the cert's role
// OIDs (as returned by extractor) to intersect allowed. An empty allowed
// slice means "no constraint" — the check passes regardless of what the cert
// asserts. A nil extractor falls back to [DefaultRoleOIDExtractor].
//
// On failure the returned error wraps [ErrRoleOIDMissing] and lists what
// the cert asserted vs. what was required.
func CheckRoleOID(extractor RoleOIDExtractorFunc, allowed ...asn1.ObjectIdentifier) CertificateCheck {
	if extractor == nil {
		extractor = DefaultRoleOIDExtractor
	}
	return func(_ context.Context, cert *x509.Certificate) error {
		if len(allowed) == 0 {
			return nil
		}
		have, err := extractor(cert)
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
