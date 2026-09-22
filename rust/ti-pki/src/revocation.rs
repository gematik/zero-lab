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
