package gempki

import (
	"context"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
)

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

// CheckAnyCertificatePolicy returns a [CertificateCheck] that passes when
// cert.PolicyIdentifiers contains at least one OID from allowed. Useful when
// a profile accepts multiple policy revisions.
func CheckAnyCertificatePolicy(allowed ...asn1.ObjectIdentifier) CertificateCheck {
	return func(_ context.Context, cert *x509.Certificate) error {
		if len(allowed) == 0 {
			return nil
		}
		for _, want := range allowed {
			if hasPolicyIdentifier(cert, want) {
				return nil
			}
		}
		return &ValidationError{
			Code:    ErrCodePolicyMismatch,
			Subject: cert.Subject.CommonName,
			Message: fmt.Sprintf("certificate asserts none of the allowed policies: have %s, want any of %s",
				oidsToString(cert.PolicyIdentifiers), oidsToString(allowed)),
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
