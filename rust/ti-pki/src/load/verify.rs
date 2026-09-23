//! The bridge from loaded bytes to verified trust material: the A_28419 roots walk
//! from the configured anchor, and the TSL signature. The TSL check is not ported from
//! `go/gempki` yet; until it is, [`verify_material`] panics, and the loading layer's
//! tests inject their own verifier.

use super::artifact::TrustMaterial;
use crate::time::Timestamp;
use crate::{Certificate, TrustConfig};

/// Loaded material that passed verification.
#[derive(Clone, Debug)]
pub struct Verified {
    /// The roots that chain to the anchor.
    pub(crate) roots: Vec<Certificate>,
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
    let tsl = crate::tsl::verify_tsl(&material.tsl)?;
    Ok(Verified {
        roots,
        tsl_next_update: tsl.next_update,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "gempki-port: enable once the roots walk and TSL signature are ported"]
    fn embedded_prod_material_verifies() {
        let config = TrustConfig::preset_prod();
        let meta = super::super::Meta {
            etag: None,
            last_modified: None,
            fetched_at: Timestamp(0),
            max_age: None,
            source: super::super::Source::Embedded,
        };
        let material = TrustMaterial::new(config.roots.to_vec(), meta.clone(), Vec::new(), meta);
        verify_material(&config, &material, Timestamp(0)).unwrap();
    }
}
