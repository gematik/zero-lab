//! Errors of the crate's own API ([`Error`]) and the findings of a validation
//! ([`ValidationError`], [`ValidationWarning`]), each carrying a stable, machine-readable
//! [`ErrorCode`]. A validation result reports findings rather than returning [`Error`],
//! so a rejected certificate is an outcome, not a failure of the call.

use core::fmt;
use std::sync::Arc;

/// Failure of a call into the crate, as opposed to a certificate that failed
/// validation.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// DER input could not be decoded.
    #[error("DER decoding failed: {0}")]
    Der(#[from] der::Error),

    /// PEM input could not be decoded.
    #[error("PEM decoding failed: {0}")]
    Pem(#[from] pem_rfc7468::Error),

    /// A certificate decoded as DER but a structure inside it is not what its
    /// specification allows.
    #[error("malformed {what}: {reason}")]
    Malformed {
        /// The structure, e.g. `admission extension`.
        what: &'static str,
        /// What is wrong with it.
        reason: String,
    },

    /// The parts of a [`TrustConfig`](crate::TrustConfig) contradict each other or
    /// the tier it is used in.
    #[error("inconsistent trust configuration: {reason}")]
    InconsistentConfig {
        /// Which rule the configuration broke.
        reason: &'static str,
    },
}

/// Stable identifier for a validation failure reason. Callers match on the
/// code rather than on message text.
///
/// The string forms ([`ErrorCode::as_str`]) are identical to the Go
/// implementation's, and the `SE_*` references name the matching gemLibPki
/// `GemPkiException` codes, so log lines and metrics stay comparable across
/// implementations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorCode {
    /// The certificate is revoked per OCSP. (SE_1016)
    Revoked,
    /// The OCSP response signature failed verification. (SE_1033)
    OcspResponseInvalid,
    /// The OCSP responder certificate is not trusted. (SE_1023)
    OcspResponderUntrusted,
    /// The OCSP responder is unreachable or returned non-success. (SE_1029)
    OcspUnavailable,
    /// Warning only: the OCSP responder is not authorized under RFC 6960, but was
    /// accepted as a delegate of another CA of the same TSP. `ti-pki`'s own code; Go
    /// has no equivalent.
    OcspResponderNotRfc6960,
    /// A required profession or role OID is not present in the admission
    /// extension. (SE_1036)
    RoleOidMissing,
    /// The certificate's notAfter is in the past. (SE_1018)
    Expired,
    /// The certificate's notBefore is in the future. (SE_1018)
    NotYetValid,
    /// The chain cannot be built to a trusted root, or an
    /// AuthorityKeyIdentifier/SubjectKeyIdentifier mismatch was detected.
    /// (SE_1041)
    ChainIncomplete,
    /// A required CertificatePolicy OID is not asserted.
    PolicyMismatch,
    /// Signature verification failed at some level of the chain.
    SignatureInvalid,
    /// A required KeyUsage or ExtendedKeyUsage is missing.
    KeyUsageMismatch,
    /// The end-entity public key is of a kind gemSpec_Krypt never admitted
    /// for a TI certificate.
    KeyNotAdmissible,
    /// Warning only: the end-entity public key is past its gemSpec_Krypt
    /// "zulässig bis" date.
    KeyPhasedOut,
    /// Automatic profile selection found no Tab_PKI_405 type marker and the
    /// admission fallback could not infer one; only the chain was validated.
    ProfileNotDetected,
    /// Automatic profile selection found several profiles for the type and
    /// none claims it; only the chain was validated.
    ProfileAmbiguous,
    /// An explicitly chosen profile does not accept the detected type;
    /// validation ran under it anyway.
    ProfileTypeMismatch,
}

impl ErrorCode {
    /// The stable string form, as used in logs and by the Go implementation.
    pub const fn as_str(self) -> &'static str {
        match self {
            ErrorCode::Revoked => "revoked",
            ErrorCode::OcspResponseInvalid => "ocsp_response_invalid",
            ErrorCode::OcspResponderUntrusted => "ocsp_responder_untrusted",
            ErrorCode::OcspUnavailable => "ocsp_unavailable",
            ErrorCode::OcspResponderNotRfc6960 => "ocsp_responder_not_rfc6960",
            ErrorCode::RoleOidMissing => "role_oid_missing",
            ErrorCode::Expired => "expired",
            ErrorCode::NotYetValid => "not_yet_valid",
            ErrorCode::ChainIncomplete => "chain_incomplete",
            ErrorCode::PolicyMismatch => "policy_mismatch",
            ErrorCode::SignatureInvalid => "signature_invalid",
            ErrorCode::KeyUsageMismatch => "key_usage_mismatch",
            ErrorCode::KeyNotAdmissible => "key_not_admissible",
            ErrorCode::KeyPhasedOut => "key_phased_out",
            ErrorCode::ProfileNotDetected => "profile_not_detected",
            ErrorCode::ProfileAmbiguous => "profile_ambiguous",
            ErrorCode::ProfileTypeMismatch => "profile_type_mismatch",
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A single validation failure, usually attributable to one certificate of a chain.
/// Several of them make up a [`ValidationResult`](crate::validate::ValidationResult).
#[derive(Clone, Debug, thiserror::Error)]
pub struct ValidationError {
    /// Why validation failed.
    pub code: ErrorCode,
    /// Common name of the offending certificate; empty if not certificate-specific.
    pub subject: String,
    /// Human-readable detail.
    pub message: String,
    /// The underlying error, if any.
    #[source]
    pub cause: Option<Arc<dyn std::error::Error + Send + Sync>>,
}

impl ValidationError {
    /// A finding with `code` and `message`, not tied to a certificate.
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        ValidationError {
            code,
            subject: String::new(),
            message: message.into(),
            cause: None,
        }
    }

    /// Attributes the finding to the certificate with common name `subject`.
    #[must_use]
    pub fn with_subject(mut self, subject: impl Into<String>) -> Self {
        self.subject = subject.into();
        self
    }

    /// Records the underlying error.
    #[must_use]
    pub fn with_cause(mut self, cause: impl std::error::Error + Send + Sync + 'static) -> Self {
        self.cause = Some(Arc::new(cause));
        self
    }
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ti-pki[{}]: {}", self.code, self.message)?;
        if !self.subject.is_empty() {
            write!(f, ": {:?}", self.subject)?;
        }
        if let Some(cause) = &self.cause {
            write!(f, ": {cause}")?;
        }
        Ok(())
    }
}

/// A non-fatal observation about a validated chain. Warnings never make a
/// [`ValidationResult`](crate::validate::ValidationResult) invalid.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidationWarning {
    /// What was observed.
    pub code: ErrorCode,
    /// Common name of the certificate concerned; empty if not certificate-specific.
    pub subject: String,
    /// Human-readable detail.
    pub message: String,
}

impl ValidationWarning {
    /// A warning with `code` and `message`, not tied to a certificate.
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        ValidationWarning {
            code,
            subject: String::new(),
            message: message.into(),
        }
    }

    /// Attributes the warning to the certificate with common name `subject`.
    #[must_use]
    pub fn with_subject(mut self, subject: impl Into<String>) -> Self {
        self.subject = subject.into();
        self
    }
}

impl fmt::Display for ValidationWarning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ti-pki[{}] warning: {}", self.code, self.message)?;
        if !self.subject.is_empty() {
            write!(f, ": {:?}", self.subject)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_names_code_message_subject_and_cause() {
        let code_only = ValidationError::new(ErrorCode::Revoked, "msg").to_string();
        assert_eq!(code_only, "ti-pki[revoked]: msg");

        let with_subject = ValidationError::new(ErrorCode::Expired, "msg").with_subject("CN=a");
        assert_eq!(with_subject.to_string(), r#"ti-pki[expired]: msg: "CN=a""#);

        let cause = std::io::Error::other("aki mismatch");
        let with_cause = ValidationError::new(ErrorCode::ChainIncomplete, "msg").with_cause(cause);
        assert_eq!(
            with_cause.to_string(),
            "ti-pki[chain_incomplete]: msg: aki mismatch"
        );
    }

    #[test]
    fn source_exposes_the_cause() {
        use std::error::Error as _;
        let error = ValidationError::new(ErrorCode::OcspUnavailable, "down")
            .with_cause(std::io::Error::other("connection refused"));
        assert_eq!(error.source().unwrap().to_string(), "connection refused");
        assert!(
            ValidationError::new(ErrorCode::Revoked, "x")
                .source()
                .is_none()
        );
    }

    #[test]
    fn warning_display() {
        let warning =
            ValidationWarning::new(ErrorCode::KeyPhasedOut, "RSA 2048").with_subject("ee");
        assert_eq!(
            warning.to_string(),
            r#"ti-pki[key_phased_out] warning: RSA 2048: "ee""#
        );
    }
}
