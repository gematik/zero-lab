//! The bridge from loaded bytes to verified trust material. The two checks it calls,
//! the A_28419 roots walk and the TSL signature, are not ported from `go/gempki` yet;
//! until they are, [`verify_material`] panics, and the loading layer's tests inject
//! their own verifier.

use x509_cert::Certificate;

use super::artifact::TrustMaterial;
use super::clock::Timestamp;
use crate::TrustConfig;

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

pub(crate) type VerifyFn = fn(&TrustConfig, &TrustMaterial) -> Result<Verified, VerifyError>;

pub(crate) fn verify_material(
    config: &TrustConfig,
    material: &TrustMaterial,
) -> Result<Verified, VerifyError> {
    let roots = crate::roots::verify_roots_json(&config.anchor, &material.roots)?;
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
        verify_material(&config, &material).unwrap();
    }
}
