package gempki

import (
	"context"
	"crypto/x509"
	"fmt"
	"slices"
	"strings"
)

// CertificateCheck is a per-certificate predicate executed by
// [ValidatePath]. A non-nil return is recorded as a [ValidationError] in
// the [ValidationResult].
//
// Checks should be cheap and side-effect-free — they may be invoked many
// times across a hot validation path. Long-running work (e.g. OCSP) belongs
// in the Phase 4 revocation subsystem, not in a CertificateCheck.
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

// CheckExtKeyUsage returns a CertificateCheck that verifies cert.ExtKeyUsage
// contains every entry in required. ExtKeyUsageAny in the cert satisfies any
// required EKU (RFC 5280 §4.2.1.12 allows ANY as a wildcard).
//
// Returns [*ValidationError] with [ErrCodeKeyUsageMismatch] on failure.
func CheckExtKeyUsage(required ...x509.ExtKeyUsage) CertificateCheck {
	return func(_ context.Context, cert *x509.Certificate) error {
		if hasExtKeyUsage(cert, x509.ExtKeyUsageAny) {
			return nil
		}
		for _, want := range required {
			if !hasExtKeyUsage(cert, want) {
				return &ValidationError{
					Code:    ErrCodeKeyUsageMismatch,
					Subject: cert.Subject.CommonName,
					Message: fmt.Sprintf("required ExtKeyUsage %s missing", describeExtKeyUsage(want)),
				}
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
