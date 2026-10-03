//! The bridge from loaded bytes to verified trust material: the A_28419 roots walk from
//! the configured anchor, then the TSL verified against the configured TSL signer CA
//! (`spec/tsl-xmldsig` parts A, B and D, [`crate::tsl_signature`]) and compared with the
//! stored list, and its CAs matched to the roots the walk yielded. The signer's OCSP
//! status (part C) needs a network and is the [`Reloader`](super::Reloader)'s step.

use super::artifact::TrustMaterial;
use crate::time::Timestamp;
use crate::tsl_signature::{Sequence, TslError, TslState, VerifiedTsl};
use crate::{Certificate, TrustConfig};

/// Loaded material that passed verification.
#[derive(Clone, Debug)]
pub struct Verified {
    /// The roots that chain to the anchor.
    pub(crate) roots: Vec<Certificate>,
    /// The TSL's CAs that a root signed.
    pub(crate) intermediates: Vec<crate::tsl::Intermediate>,
    /// The TSL's `NextUpdate`.
    pub(crate) tsl_next_update: Option<Timestamp>,
    /// The verified TSL; `None` only for test material.
    pub(crate) tsl: Option<VerifiedTsl>,
    /// How the TSL relates to the stored one.
    pub(crate) sequence: Sequence,
}

/// Why loaded material was rejected. Always a hard failure: possible tampering.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("verification failed: {reason}")]
pub struct VerifyError {
    /// What failed.
    pub reason: String,
    /// The result code and rule, when the TSL failed (`spec/tsl-xmldsig`).
    pub tsl: Option<TslError>,
}

impl VerifyError {
    pub(crate) fn new(reason: impl Into<String>) -> Self {
        VerifyError {
            reason: reason.into(),
            tsl: None,
        }
    }
}

impl From<TslError> for VerifyError {
    fn from(error: TslError) -> Self {
        VerifyError {
            reason: format!("TSL: {error}"),
            tsl: Some(error),
        }
    }
}

pub(crate) type VerifyFn =
    fn(&TrustConfig, &TrustMaterial, Timestamp, Option<&TslState>) -> Result<Verified, VerifyError>;

pub(crate) fn verify_material(
    config: &TrustConfig,
    material: &TrustMaterial,
    now: Timestamp,
    stored: Option<&TslState>,
) -> Result<Verified, VerifyError> {
    let roots =
        crate::roots::verify_roots_json(&config.anchor, &material.roots, now, &config.algorithms)?;
    let tsl = verify_tsl(config, &material.tsl, now)?;
    let sequence = tsl.check_sequence(stored)?;
    let store = crate::TrustStore::new(roots.iter().cloned());
    let matched =
        crate::tsl::match_to_roots(tsl.tsl.intermediate_cas(), &store, &config.algorithms);
    Ok(Verified {
        roots,
        intermediates: matched.intermediates,
        tsl_next_update: tsl.tsl.next_update,
        tsl: Some(tsl),
        sequence,
    })
}

#[cfg(feature = "brainpool")]
fn verify_tsl(
    config: &TrustConfig,
    xml: &[u8],
    now: Timestamp,
) -> Result<VerifiedTsl, VerifyError> {
    Ok(crate::tsl::Tsl::parse_verified(xml, config, now)?)
}

/// Every TSL is signed on brainpoolP256r1 (TSLSIG-012): without the curve none verifies.
#[cfg(not(feature = "brainpool"))]
fn verify_tsl(_: &TrustConfig, _: &[u8], _: Timestamp) -> Result<VerifiedTsl, VerifyError> {
    Err(VerifyError::new(
        "the TSL is signed on brainpoolP256r1, which needs the brainpool feature",
    ))
}

#[cfg(all(test, feature = "brainpool"))]
mod tests {
    use super::*;

    #[test]
    fn embedded_prod_material_verifies() {
        let config = TrustConfig::preset_prod();
        let meta = super::super::Meta {
            etag: None,
            last_modified: None,
            fetched_at: Timestamp(0),
            max_age: None,
            source: super::super::Source::Embedded,
        };
        let tsl = include_bytes!("../../tests/fixtures/tsl/ECC-RSA_TSL.xml");
        let material = TrustMaterial::new(config.roots.to_vec(), meta.clone(), tsl.to_vec(), meta);
        // The fixture TSL's ListIssueDateTime, 2026-09-13T23:00:08Z.
        let verified = verify_material(&config, &material, Timestamp(1_789_340_408), None).unwrap();
        assert_eq!(verified.roots.len(), 10);
        assert_eq!(verified.intermediates.len(), 84);
        assert_eq!(
            verified.tsl_next_update.map(|t| t.to_string()).as_deref(),
            Some("2026-10-13T23:00:08Z")
        );

        let broken = TrustMaterial::new(
            config.roots.to_vec(),
            material.meta(super::super::Artifact::Tsl).clone(),
            b"<html/>".to_vec(),
            material.meta(super::super::Artifact::Tsl).clone(),
        );
        let error = verify_material(&config, &broken, Timestamp(1_789_340_408), None).unwrap_err();
        assert!(error.reason.contains("TSL"), "{error}");
    }
}
