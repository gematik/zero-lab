package gempki

import (
	"errors"
	"fmt"
)

// ErrRSANotSupported is the sentinel for the one remaining RSA-rejection
// path: the TSL detached-signature parser ([ParseTSLDetachedSignature])
// only knows the ECDSA-Sig-Value structure. The .sig file's RSA-PSS
// variant has a different on-disk shape that this library doesn't decode
// yet.
//
// For every other surface (parsing certificates, building a TrustStore,
// chain validation), RSA is accepted: historical TI roots (GEM.RCA1/2/6)
// are RSA-keyed and must be loadable for end-to-end chain validation to
// work.
var ErrRSANotSupported = errors.New(
	"gempki: RSA-PSS TSL signatures are not decoded yet — only the ECDSA TSL .sig file is supported",
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
	// (Ed25519, P-521, secp256k1, ...). RSA is no longer flagged here.
	ErrCodeUnsupportedCrypto ErrorCode = "unsupported_crypto"

	// ErrCodeProfileNotDetected — a profile-driven verify ran in auto mode
	// but the cert carries no Tab_PKI_405 type marker and the Admission
	// fallback couldn't infer one. The chain-only result is still returned,
	// but role/policy/OCSP enforcement was skipped — callers using --profile
	// auto should treat this as a loud "we didn't do everything you asked".
	ErrCodeProfileNotDetected ErrorCode = "profile_not_detected"

	// ErrCodeProfileAmbiguous — auto mode detected the cert type, multiple
	// profiles accept that type, and none of them claims default-for
	// ownership. Validation falls back to chain-only; callers must pass
	// --profile explicitly to pick one.
	//
	// The canonical example is C.FD.AUT, accepted by both `epavau` (ePA
	// VAU authenticity) and `idp` (IDP authenticity).
	ErrCodeProfileAmbiguous ErrorCode = "profile_ambiguous"

	// ErrCodeProfileTypeMismatch — the user passed --profile X explicitly,
	// but the detected cert type isn't in X.AcceptsTypes. Validation
	// proceeds (the user is forcing the profile) but the warning surfaces
	// the mismatch loudly.
	ErrCodeProfileTypeMismatch ErrorCode = "profile_type_mismatch"
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

// WarnProfileNotDetected is the sentinel used by auto-profile callers when
// [DetectCertificateType] returns [CertTypeUnknown]. It is a warning, not
// an error, so [ValidationResult].Valid stays true while the caller is
// notified that profile-driven checks were skipped.
var WarnProfileNotDetected = &ValidationWarning{
	Code:    ErrCodeProfileNotDetected,
	Message: "cert type could not be auto-detected; ran chain-only validation (pass --profile explicitly or use --profile none to silence)",
}

// WarnProfileAmbiguous is the sentinel used by auto-profile callers when
// the cert type is known but multiple profiles accept it and none owns
// the default. Callers should fill Subject and append a message that
// names the candidates (the bare sentinel carries only the code).
var WarnProfileAmbiguous = &ValidationWarning{
	Code:    ErrCodeProfileAmbiguous,
	Message: "cert type matches multiple profiles; pass --profile explicitly to pick one",
}

// WarnProfileTypeMismatch is the sentinel used when --profile X is forced
// against a cert whose detected type isn't in X.AcceptsTypes. Validation
// still runs under X; this warning records the override.
var WarnProfileTypeMismatch = &ValidationWarning{
	Code:    ErrCodeProfileTypeMismatch,
	Message: "explicit profile does not accept the detected cert type; running validation anyway",
}

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
