//! Revocation policy: which checker consults which source, and how its
//! outcome affects the verdict. Revocation is decided by one table:
//!
//! ```text
//! outcome                          HardFail  SoftFail
//! Good                             —         —
//! Revoked                          error     error
//! Unknown / responder unavailable  error     warning
//! responder untrusted / invalid    error     error
//! ```
//!
//! The last row is deliberate: a response that failed authorization or
//! signature verification is evidence of something wrong, not of a flaky
//! responder, and no mode turns it into a warning.

use core::fmt;

use crate::Certificate;
use crate::error::{ErrorCode, ValidationError, ValidationWarning};
use crate::time::Timestamp;

/// How a non-Good revocation outcome affects the verdict. Revoked and an
/// untrusted response are always errors; the mode only governs the
/// transient cases.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum RevocationMode {
    /// Reject on anything other than Good. The default, so a validator that
    /// forgets to configure revocation fails closed rather than open.
    #[default]
    HardFail,
    /// Record Unknown and transient failures as warnings and accept the
    /// certificate.
    SoftFail,
    /// Skip revocation checking entirely.
    Disabled,
}

/// What a source said about one certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RevocationStatus {
    /// The source says the certificate is valid.
    Good,
    /// The source says the certificate is revoked.
    Revoked,
    /// The source has no usable information: it does not know the certificate, there
    /// is no source to ask, or its answer is too old to use.
    Unknown,
}

impl RevocationStatus {
    /// `good`, `revoked` or `unknown`, as in `gempki`.
    pub const fn as_str(self) -> &'static str {
        match self {
            RevocationStatus::Good => "good",
            RevocationStatus::Revoked => "revoked",
            RevocationStatus::Unknown => "unknown",
        }
    }
}

impl fmt::Display for RevocationStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The revocation outcome for one certificate, with the OCSP detail for display and
/// diagnostics.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevocationResult {
    /// What the source said.
    pub status: RevocationStatus,
    /// When the check ran.
    pub checked_at: Timestamp,
    /// When the certificate was revoked; only with [`RevocationStatus::Revoked`].
    pub revoked_at: Option<Timestamp>,
    /// The revocation reason (`keyCompromise`, …), or why the status is unknown.
    pub reason: String,
    /// The OCSP endpoint queried; empty if none was.
    pub responder_url: String,
    /// `producedAt` of the response.
    pub produced_at: Option<Timestamp>,
    /// `thisUpdate` of the single response.
    pub this_update: Option<Timestamp>,
    /// `nextUpdate` of the single response, if the responder set one.
    pub next_update: Option<Timestamp>,
    /// The delegated responder's certificate; `None` when the issuer signed itself.
    pub responder: Option<Certificate>,
    /// Common name of whoever signed the response.
    pub responder_name: String,
    /// The DER response as received, for forensic dumps.
    pub raw_response: Vec<u8>,
}

impl RevocationResult {
    /// An [`Unknown`](RevocationStatus::Unknown) result for a certificate no source
    /// could answer for.
    pub fn unknown(checked_at: Timestamp, reason: impl Into<String>) -> Self {
        RevocationResult {
            status: RevocationStatus::Unknown,
            checked_at,
            revoked_at: None,
            reason: reason.into(),
            responder_url: String::new(),
            produced_at: None,
            this_update: None,
            next_update: None,
            responder: None,
            responder_name: String::new(),
            raw_response: Vec::new(),
        }
    }
}

/// One source of revocation truth: [`OcspChecker`](crate::ocsp::OcspChecker), or a
/// stub in tests.
///
/// The contract separates two kinds of outcome a caller must never confuse:
///
/// - `Ok`: the source answered. Good, Revoked or Unknown — Unknown covering "the
///   responder does not know", "no responder URL" and "the answer is too old to use".
/// - `Err`: the source could not be consulted, or its answer cannot be trusted. The
///   code says which: [`ErrorCode::OcspUnavailable`] for a transient failure
///   (unreachable, HTTP error, undecodable bytes), [`ErrorCode::OcspResponderUntrusted`]
///   and [`ErrorCode::OcspResponseInvalid`] for a response that failed authorization,
///   binding or signature verification.
#[allow(
    async_fn_in_trait,
    reason = "no Send bound on purpose: implementable on wasm32"
)]
pub trait RevocationChecker {
    /// The status of `cert`, which `issuer` issued.
    async fn check(
        &self,
        cert: &Certificate,
        issuer: &Certificate,
    ) -> Result<RevocationResult, ValidationError>;
}

/// The checker for a validator that has no revocation source: every check fails with
/// [`ErrorCode::OcspUnavailable`], so under [`HardFail`](RevocationMode::HardFail) a
/// forgotten checker rejects instead of silently accepting. Pair it with
/// [`RevocationMode::Disabled`] to validate offline on purpose.
#[derive(Clone, Copy, Debug, Default)]
pub struct Unchecked;

impl RevocationChecker for Unchecked {
    async fn check(
        &self,
        cert: &Certificate,
        _issuer: &Certificate,
    ) -> Result<RevocationResult, ValidationError> {
        Err(ValidationError::new(
            ErrorCode::OcspUnavailable,
            "no revocation checker configured (disable revocation to skip it)",
        )
        .with_subject(cert.subject_cn()))
    }
}

/// What [`apply_revocation`] makes of an outcome.
#[derive(Clone, Debug)]
pub enum RevocationFinding {
    /// The certificate is rejected.
    Error(ValidationError),
    /// The certificate is accepted with a warning.
    Warning(ValidationWarning),
}

/// Maps one checker outcome for the certificate with common name `subject` onto the
/// result vocabulary, following the table in the [module docs](self). The single
/// place the mode is interpreted; `None` means nothing to report.
pub fn apply_revocation(
    mode: RevocationMode,
    subject: &str,
    outcome: &Result<RevocationResult, ValidationError>,
) -> Option<RevocationFinding> {
    let soft = match mode {
        RevocationMode::Disabled => return None,
        RevocationMode::SoftFail => true,
        RevocationMode::HardFail => false,
    };
    match outcome {
        Err(error) => {
            let mut error = error.clone();
            if error.subject.is_empty() {
                subject.clone_into(&mut error.subject);
            }
            let untrusted = matches!(
                error.code,
                ErrorCode::OcspResponderUntrusted | ErrorCode::OcspResponseInvalid
            );
            if soft && !untrusted {
                return Some(RevocationFinding::Warning(
                    ValidationWarning::new(error.code, error.message).with_subject(error.subject),
                ));
            }
            Some(RevocationFinding::Error(error))
        }
        Ok(result) => match result.status {
            RevocationStatus::Good => None,
            RevocationStatus::Revoked => Some(RevocationFinding::Error(
                ValidationError::new(
                    ErrorCode::Revoked,
                    format!(
                        "certificate revoked at {}: {}",
                        result
                            .revoked_at
                            .map_or_else(|| "an unknown time".to_owned(), |t| t.to_string()),
                        result.reason
                    ),
                )
                .with_subject(subject),
            )),
            RevocationStatus::Unknown => {
                let message = format!("revocation status unknown: {}", result.reason);
                Some(if soft {
                    RevocationFinding::Warning(
                        ValidationWarning::new(ErrorCode::OcspUnavailable, message)
                            .with_subject(subject),
                    )
                } else {
                    RevocationFinding::Error(
                        ValidationError::new(ErrorCode::OcspUnavailable, message)
                            .with_subject(subject),
                    )
                })
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn result(status: RevocationStatus) -> RevocationResult {
        RevocationResult {
            status,
            revoked_at: Some(Timestamp(1_764_547_200)),
            reason: "keyCompromise".into(),
            ..RevocationResult::unknown(Timestamp(0), "")
        }
    }

    fn describe(finding: Option<RevocationFinding>) -> String {
        match finding {
            None => "-".into(),
            Some(RevocationFinding::Error(e)) => format!("error {e}"),
            Some(RevocationFinding::Warning(w)) => format!("warning {w}"),
        }
    }

    #[test]
    fn the_revocation_table() {
        let unavailable = ValidationError::new(ErrorCode::OcspUnavailable, "down");
        let untrusted = ValidationError::new(ErrorCode::OcspResponderUntrusted, "rogue");
        let invalid = ValidationError::new(ErrorCode::OcspResponseInvalid, "bad signature");
        let revoked = "error ti-pki[revoked]: certificate revoked at 2025-12-01T00:00:00Z: \
                       keyCompromise: \"ee\"";
        let unknown = "revocation status unknown: keyCompromise: \"ee\"";
        for (outcome, hard, soft) in [
            (
                Ok(result(RevocationStatus::Good)),
                "-".to_owned(),
                "-".to_owned(),
            ),
            (
                Ok(result(RevocationStatus::Revoked)),
                revoked.into(),
                revoked.into(),
            ),
            (
                Ok(result(RevocationStatus::Unknown)),
                format!("error ti-pki[ocsp_unavailable]: {unknown}"),
                format!("warning ti-pki[ocsp_unavailable] warning: {unknown}"),
            ),
            (
                Err(unavailable),
                "error ti-pki[ocsp_unavailable]: down: \"ee\"".into(),
                "warning ti-pki[ocsp_unavailable] warning: down: \"ee\"".into(),
            ),
            (
                Err(untrusted),
                "error ti-pki[ocsp_responder_untrusted]: rogue: \"ee\"".into(),
                "error ti-pki[ocsp_responder_untrusted]: rogue: \"ee\"".into(),
            ),
            (
                Err(invalid),
                "error ti-pki[ocsp_response_invalid]: bad signature: \"ee\"".into(),
                "error ti-pki[ocsp_response_invalid]: bad signature: \"ee\"".into(),
            ),
        ] {
            assert_eq!(
                describe(apply_revocation(RevocationMode::HardFail, "ee", &outcome)),
                hard
            );
            assert_eq!(
                describe(apply_revocation(RevocationMode::SoftFail, "ee", &outcome)),
                soft
            );
            assert!(apply_revocation(RevocationMode::Disabled, "ee", &outcome).is_none());
        }
    }

    #[test]
    fn a_subject_already_set_is_kept() {
        let error = ValidationError::new(ErrorCode::OcspUnavailable, "down").with_subject("ca");
        let Some(RevocationFinding::Error(error)) =
            apply_revocation(RevocationMode::HardFail, "ee", &Err(error))
        else {
            panic!("expected an error")
        };
        assert_eq!(error.subject, "ca");
    }
}
