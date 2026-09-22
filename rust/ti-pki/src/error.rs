//! Errors of the crate's own API ([`Error`]) and the stable, machine-readable
//! reasons a certificate fails validation ([`ErrorCode`]). A validation result
//! reports findings as codes rather than as [`Error`] values, so a rejected
//! certificate is an outcome, not a failure of the call.

/// Failure of a call into the crate, as opposed to a certificate that failed
/// validation.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The environment name is not one of `prod`, `test`, `ref`, `dev`.
    #[error("unknown environment {0:?}, expected one of prod, test, ref, dev")]
    UnknownEnvironment(String),

    /// DER input could not be decoded.
    #[error("DER decoding failed: {0}")]
    Der(#[from] der::Error),
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
