//! The validator and its result. Validation runs chain building, path
//! validation, the gemSpec_Krypt key admissibility check and the revocation
//! check, and folds every finding into one result: whether the certificate is
//! valid, the errors with an [`ErrorCode`] each, the warnings,
//! and the built chain with each certificate's position.

use core::fmt;

use crate::Certificate;
use crate::error::{ErrorCode, ValidationError, ValidationWarning};

/// A certificate's role in a validated chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ChainPosition {
    /// The end entity, the certificate the caller asked about.
    EndEntity,
    /// An intermediate CA between the end entity and the root.
    SubCa,
    /// The trusted root.
    Root,
}

impl ChainPosition {
    /// The stable string form, as in `gempki`: `end_entity`, `sub_ca`, `root`.
    pub const fn as_str(self) -> &'static str {
        match self {
            ChainPosition::EndEntity => "end_entity",
            ChainPosition::SubCa => "sub_ca",
            ChainPosition::Root => "root",
        }
    }
}

impl fmt::Display for ChainPosition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What validation recorded about one certificate of the chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertResult {
    /// The certificate's common name.
    pub subject: String,
    /// Its role in the chain.
    pub position: ChainPosition,
}

/// The outcome of one validation.
///
/// `valid` is true only when every check passed; `errors` lists what made it false.
/// `warnings` are observations that did not affect the verdict. `chain`, `positions` and
/// `cert_results` are parallel: `chain[i]` sits at `positions[i]` and is detailed in
/// `cert_results[i]`.
#[derive(Clone, Debug, Default)]
pub struct ValidationResult {
    /// Whether the certificate is valid.
    pub valid: bool,
    /// The chain as built, end entity first.
    pub chain: Vec<Certificate>,
    /// The role of each chain element.
    pub positions: Vec<ChainPosition>,
    /// Why the certificate is not valid.
    pub errors: Vec<ValidationError>,
    /// Non-fatal observations.
    pub warnings: Vec<ValidationWarning>,
    /// Per-certificate detail.
    pub cert_results: Vec<CertResult>,
}

impl ValidationResult {
    /// Whether any error carries `code`, e.g. to tell revoked from expired.
    pub fn has_error(&self, code: ErrorCode) -> bool {
        self.errors.iter().any(|e| e.code == code)
    }

    /// Whether any warning carries `code`.
    pub fn has_warning(&self, code: ErrorCode) -> bool {
        self.warnings.iter().any(|w| w.code == code)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn has_error_matches_by_code() {
        let result = ValidationResult {
            errors: vec![ValidationError::new(ErrorCode::Expired, "expired")],
            warnings: vec![ValidationWarning::new(ErrorCode::KeyPhasedOut, "RSA 2048")],
            ..ValidationResult::default()
        };
        assert!(result.has_error(ErrorCode::Expired));
        assert!(!result.has_error(ErrorCode::Revoked));
        assert!(result.has_warning(ErrorCode::KeyPhasedOut));
        assert_eq!(ChainPosition::SubCa.to_string(), "sub_ca");
    }
}
