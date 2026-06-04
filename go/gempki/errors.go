package gempki

import (
	"errors"
	"fmt"
)

// ErrRSANotSupported is returned whenever an RSA public key is encountered
// anywhere in a certificate chain, OCSP response, or other PKI artifact.
//
// The TI-PKI migrated from RSA to ECC; this library accepts only Brainpool
// (P256r1, P384r1) and NIST (P-256, P-384) elliptic curves per gemSpec_Krypt.
// There is no opt-in to enable RSA. The error message references gemSpec_Krypt
// so failures are easy to triage in production.
var ErrRSANotSupported = errors.New(
	"gempki: RSA is not supported — the TI-PKI requires ECC (Brainpool or NIST). See gemSpec_Krypt",
)

// ErrorCode is a stable, machine-readable identifier for a validation failure
// reason. Callers should switch on ErrorCode rather than parsing error strings.
//
// Codes mirror the gemLibPki GemPkiException error codes where a clear
// equivalent exists (e.g. SE_1016 → ErrCodeRevoked); the full mapping is in
// the package documentation.
type ErrorCode string

// Validation error codes.
//
// The SE_* references map to the gemLibPki Java reference implementation's
// GemPkiException error codes so log lines and metrics stay comparable across
// the two implementations.
const (
	// ErrCodeRevoked — the certificate is revoked per OCSP. (SE_1016)
	ErrCodeRevoked ErrorCode = "revoked"

	// ErrCodeOCSPResponseInvalid — OCSP response signature failed verification. (SE_1033)
	ErrCodeOCSPResponseInvalid ErrorCode = "ocsp_response_invalid"

	// ErrCodeOCSPResponderUntrusted — OCSP responder certificate is not trusted. (SE_1023)
	ErrCodeOCSPResponderUntrusted ErrorCode = "ocsp_responder_untrusted"

	// ErrCodeOCSPUnavailable — OCSP responder is unreachable or returned non-success. (SE_1029)
	ErrCodeOCSPUnavailable ErrorCode = "ocsp_unavailable"

	// ErrCodeRoleOIDMissing — required profession/role OID not present in admission extension. (SE_1036)
	ErrCodeRoleOIDMissing ErrorCode = "role_oid_missing"

	// ErrCodeExpired — certificate notAfter is in the past. (SE_1018)
	ErrCodeExpired ErrorCode = "expired"

	// ErrCodeNotYetValid — certificate notBefore is in the future. (SE_1018)
	ErrCodeNotYetValid ErrorCode = "not_yet_valid"

	// ErrCodeChainIncomplete — chain cannot be built to a trusted root,
	// or an AuthorityKeyIdentifier/SubjectKeyIdentifier mismatch was detected. (SE_1041)
	ErrCodeChainIncomplete ErrorCode = "chain_incomplete"

	// ErrCodePolicyMismatch — required CertificatePolicy OID not asserted.
	ErrCodePolicyMismatch ErrorCode = "policy_mismatch"

	// ErrCodeSignatureInvalid — chain signature verification failed at some level.
	ErrCodeSignatureInvalid ErrorCode = "signature_invalid"

	// ErrCodeKeyUsageMismatch — required KeyUsage or ExtendedKeyUsage missing.
	ErrCodeKeyUsageMismatch ErrorCode = "key_usage_mismatch"

	// ErrCodeUnsupportedCrypto — key type or curve outside TI-PKI policy
	// (RSA, Ed25519, P-521, ...). Wraps [ErrRSANotSupported] for RSA cases.
	ErrCodeUnsupportedCrypto ErrorCode = "unsupported_crypto"
)

// ValidationError describes a single validation failure attributable to one
// certificate in a chain. Multiple ValidationErrors may be aggregated in a
// [ValidationResult].
//
// ValidationError supports errors.Is by Code, so callers can write
//
//	if errors.Is(err, &gempki.ValidationError{Code: gempki.ErrCodeRevoked}) { ... }
//
// or check against the sentinel values declared below
// ([ErrRevoked], [ErrExpired], …).
type ValidationError struct {
	Code    ErrorCode
	Subject string // CommonName of the offending certificate, "" if not cert-specific
	Message string
	Cause   error
}

// Error implements the error interface.
func (e *ValidationError) Error() string {
	switch {
	case e == nil:
		return "<nil ValidationError>"
	case e.Subject != "" && e.Cause != nil:
		return fmt.Sprintf("gempki[%s]: %s: %q: %v", e.Code, e.Message, e.Subject, e.Cause)
	case e.Subject != "":
		return fmt.Sprintf("gempki[%s]: %s: %q", e.Code, e.Message, e.Subject)
	case e.Cause != nil:
		return fmt.Sprintf("gempki[%s]: %s: %v", e.Code, e.Message, e.Cause)
	default:
		return fmt.Sprintf("gempki[%s]: %s", e.Code, e.Message)
	}
}

// Unwrap exposes the underlying cause for errors.Is / errors.As traversal.
func (e *ValidationError) Unwrap() error { return e.Cause }

// Is reports whether target matches this error by ErrorCode. Subject and
// Cause are ignored — they describe the specific instance, not the kind.
func (e *ValidationError) Is(target error) bool {
	var t *ValidationError
	if !errors.As(target, &t) {
		return false
	}
	return e.Code == t.Code
}

// Sentinel ValidationErrors suitable as errors.Is targets. They carry only
// the code (no Subject, no Cause) — instance-specific values are matched by
// code equality.
var (
	ErrRevoked                = &ValidationError{Code: ErrCodeRevoked, Message: "certificate is revoked"}
	ErrOCSPResponseInvalid    = &ValidationError{Code: ErrCodeOCSPResponseInvalid, Message: "OCSP response invalid"}
	ErrOCSPResponderUntrusted = &ValidationError{Code: ErrCodeOCSPResponderUntrusted, Message: "OCSP responder untrusted"}
	ErrOCSPUnavailable        = &ValidationError{Code: ErrCodeOCSPUnavailable, Message: "OCSP responder unavailable"}
	ErrRoleOIDMissing         = &ValidationError{Code: ErrCodeRoleOIDMissing, Message: "required role OID missing"}
	ErrExpired                = &ValidationError{Code: ErrCodeExpired, Message: "certificate expired"}
	ErrNotYetValid            = &ValidationError{Code: ErrCodeNotYetValid, Message: "certificate not yet valid"}
	ErrChainIncomplete        = &ValidationError{Code: ErrCodeChainIncomplete, Message: "chain incomplete"}
	ErrPolicyMismatch         = &ValidationError{Code: ErrCodePolicyMismatch, Message: "certificate policy mismatch"}
	ErrSignatureInvalid       = &ValidationError{Code: ErrCodeSignatureInvalid, Message: "signature invalid"}
	ErrKeyUsageMismatch       = &ValidationError{Code: ErrCodeKeyUsageMismatch, Message: "key usage mismatch"}
	ErrUnsupportedCrypto      = &ValidationError{Code: ErrCodeUnsupportedCrypto, Message: "unsupported crypto"}
)

// ValidationWarning is a non-fatal observation about the validated chain.
// Warnings never cause [ValidationResult].Valid to be false.
type ValidationWarning struct {
	Code    ErrorCode
	Subject string
	Message string
}

func (w *ValidationWarning) String() string {
	if w == nil {
		return "<nil ValidationWarning>"
	}
	if w.Subject != "" {
		return fmt.Sprintf("gempki[%s] warning: %s: %q", w.Code, w.Message, w.Subject)
	}
	return fmt.Sprintf("gempki[%s] warning: %s", w.Code, w.Message)
}
