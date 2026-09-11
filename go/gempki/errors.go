package gempki

import (
	"crypto/x509"
	"errors"
	"fmt"
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

// ErrChainIncomplete is the errors.Is target for chain-construction
// failures; [BuildChain] wraps it into every error it returns.
var ErrChainIncomplete = &ValidationError{Code: ErrCodeChainIncomplete, Message: "chain incomplete"}

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

// ChainPosition labels a certificate's role in a validated chain.
type ChainPosition string

const (
	// PositionEE — end-entity certificate (the leaf the caller cares about).
	PositionEE ChainPosition = "end_entity"

	// PositionSubCA — intermediate CA between the end-entity and a trusted root.
	PositionSubCA ChainPosition = "sub_ca"

	// PositionRoot — trusted root anchor.
	PositionRoot ChainPosition = "root"
)

// CertResult is what the validator recorded about one certificate of the
// chain.
type CertResult struct {
	Subject    string
	Position   ChainPosition
	Revocation *RevocationResult // nil when revocation was skipped or not run for this position
}

// ValidationResult is the outcome of a single [Validator].Validate call.
//
// Valid is true only when every check passed; Errors enumerates the
// problems that caused Valid to be false. Warnings record non-fatal
// observations that did not affect the verdict.
//
// Chain and Positions are parallel slices indexed the same way:
// Chain[i] is positioned at Positions[i] and detailed in CertResults[i].
type ValidationResult struct {
	Valid       bool
	Chain       []*x509.Certificate
	Positions   []ChainPosition
	Errors      []*ValidationError
	Warnings    []*ValidationWarning
	CertResults []CertResult
}

// HasError reports whether the result contains at least one error with the
// given code. Useful for callers that need to discriminate revoked-vs-expired
// without scanning the slice manually.
func (r *ValidationResult) HasError(code ErrorCode) bool {
	if r == nil {
		return false
	}
	for _, e := range r.Errors {
		if e != nil && e.Code == code {
			return true
		}
	}
	return false
}
