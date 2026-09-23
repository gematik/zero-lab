//! The bridge from loaded bytes to verified trust material: the A_28419 roots walk from
//! the configured anchor, then the TSL's CAs matched to the roots it yielded. The TSL
//! itself is not authenticated (see [`crate::tsl`]); a CA from it is only kept if a
//! verified root signed it.

use super::artifact::TrustMaterial;
use crate::time::Timestamp;
use crate::{Certificate, TrustConfig};

/// Loaded material that passed verification.
#[derive(Clone, Debug)]
pub struct Verified {
    /// The roots that chain to the anchor.
    pub(crate) roots: Vec<Certificate>,
    /// The TSL's CAs that a root signed.
    pub(crate) intermediates: Vec<Certificate>,
    /// The TSL's `NextUpdate`.
    pub(crate) tsl_next_update: Option<Timestamp>,
}

/// Why loaded material was rejected. Always a hard failure: possible tampering.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("verification failed: {reason}")]
pub struct VerifyError {
    /// What failed.
    pub reason: String,
}

pub(crate) type VerifyFn =
    fn(&TrustConfig, &TrustMaterial, Timestamp) -> Result<Verified, VerifyError>;

pub(crate) fn verify_material(
    config: &TrustConfig,
    material: &TrustMaterial,
    now: Timestamp,
) -> Result<Verified, VerifyError> {
    let roots =
        crate::roots::verify_roots_json(&config.anchor, &material.roots, now, &config.algorithms)?;
    let tsl = crate::tsl::Tsl::parse(&material.tsl).map_err(|e| VerifyError {
        reason: e.to_string(),
    })?;
    let store = crate::TrustStore::new(roots.iter().cloned());
    let matched = crate::tsl::match_to_roots(tsl.intermediate_cas(), &store, &config.algorithms);
    Ok(Verified {
        roots,
        intermediates: matched.intermediates,
        tsl_next_update: tsl.next_update,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "brainpool")]
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
        let verified = verify_material(&config, &material, Timestamp(1_789_340_408)).unwrap();
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
        let error = verify_material(&config, &broken, Timestamp(1_789_340_408)).unwrap_err();
        assert!(error.reason.contains("TSL"), "{error}");
    }
}
