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
