//! The findings of a TSL verification (`spec/tsl-xmldsig`), as `ti pki tsl verify`
//! reports them.

use serde::Serialize;
use ti_pki::Certificate;
use ti_pki::tsl::Rejection;
use ti_pki::tsl_signature::TslError;

use crate::{hex, sha256};

/// A result code with its Tab_PKI_274 number, the rule and what happened.
#[derive(Clone, Debug, Serialize)]
pub struct Finding {
    /// The code, e.g. `xml_signature_error`.
    pub code: &'static str,
    /// Its Tab_PKI_274 number, if it has one.
    pub code_number: Option<u16>,
    /// The rule of `spec/tsl-xmldsig`, e.g. `TSLSIG-018`.
    pub rule: &'static str,
    /// What happened, for humans; not stable.
    pub detail: String,
}

impl From<&TslError> for Finding {
    fn from(e: &TslError) -> Self {
        Finding {
            code: e.code.as_str(),
            code_number: e.code.number(),
            rule: e.rule,
            detail: e.detail.clone(),
        }
    }
}

/// A certificate named in a TSL report.
#[derive(Clone, Debug, Serialize)]
pub struct CertSummary {
    /// The subject's common name.
    pub common_name: String,
    /// The subject DN.
    pub subject: String,
    /// Hexadecimal.
    pub serial: String,
    /// RFC 3339, UTC.
    pub not_before: String,
    /// RFC 3339, UTC.
    pub not_after: String,
    /// The SHA-256 fingerprint in [`hex`].
    pub sha256: String,
}

impl CertSummary {
    /// The summary of `cert`.
    pub fn new(cert: &Certificate) -> Self {
        CertSummary {
            common_name: cert.subject_cn().to_owned(),
            subject: cert.subject().to_string(),
            serial: hex(cert.serial()),
            not_before: cert.not_before().to_string(),
            not_after: cert.not_after().to_string(),
            sha256: sha256(cert.der()),
        }
    }
}

/// Why no verified root signed a TSL CA: `not_ca`, `self_signed`, `unknown_issuer`,
/// `bad_signature`.
pub fn rejection_code(reason: Rejection) -> &'static str {
    match reason {
        Rejection::NotCa => "not_ca",
        Rejection::SelfSigned => "self_signed",
        Rejection::UnknownIssuer => "unknown_issuer",
        Rejection::BadSignature => "bad_signature",
        _ => "other",
    }
}
