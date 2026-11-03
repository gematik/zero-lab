/*
 * Copyright (Change Date see Readme), gematik GmbH
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be approved by the
 * European Commission – subsequent versions of the EUPL (the "Licence").
 * You may not use this work except in compliance with the Licence.
 *
 * You find a copy of the Licence in the "Licence" file or at
 * https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either expressed or implied.
 * In case of changes by gematik find details in the "Readme" file.
 *
 * See the Licence for the specific language governing permissions and limitations under the Licence.
 *
 * *******
 *
 * For additional notes and disclaimer from gematik and in case of changes by gematik,
 * find details in the "Readme" file.
 */

//! The bridge from loaded bytes to verified trust material: the A_28419 roots walk from
//! the configured anchor, then the TSL verified by its detached signature against the
//! configured TSL signer CA (`spec/tsl-detached`, `spec/tsl-xmldsig` parts B and D,
//! [`crate::tsl_signature`]) and compared with the
//! stored list, and its CAs matched to the roots the walk yielded. The signer's OCSP
//! status (part C) needs a network and is the [`Reloader`](super::Reloader)'s step.

use super::artifact::TrustMaterial;
use crate::time::Timestamp;
use crate::tsl_signature::{DetachedTsl, Sequence, TslError, TslState, VerifiedTsl};
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
    /// The OCSP responders the TSL lists in accord, with their TSP.
    pub(crate) ocsp_responders: Vec<(Certificate, String)>,
    /// The certificate types the TSL states for its CAs.
    pub(crate) ca_types: Vec<(Certificate, Vec<const_oid::ObjectIdentifier>)>,
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
    let files = material.detached.as_ref().map(|d| DetachedTsl {
        signature: &d.signature,
        signer_status: d.signer_status.as_ref().map(|(body, _)| body.as_slice()),
    });
    verify_bytes(config, &material.roots, &material.tsl, files, now, stored)
}

pub(crate) fn verify_bytes(
    config: &TrustConfig,
    roots_json: &[u8],
    tsl_xml: &[u8],
    files: Option<DetachedTsl<'_>>,
    now: Timestamp,
    stored: Option<&TslState>,
) -> Result<Verified, VerifyError> {
    let roots =
        crate::roots::verify_roots_json(&config.anchor, roots_json, now, &config.algorithms)?;
    let tsl = verify_tsl(config, tsl_xml, files, now)?;
    let sequence = tsl.check_sequence(stored)?;
    let store = crate::TrustStore::new(roots.iter().cloned());
    let matched =
        crate::tsl::match_to_roots(tsl.tsl.intermediate_cas(), &store, &config.algorithms);
    let ocsp_responders = tsl
        .tsl
        .services
        .iter()
        .filter(|s| s.service_type == crate::tsl::SERVICE_TYPE_OCSP && s.is_in_accord())
        .filter_map(|s| Some((s.certificate.clone()?, s.provider.clone())))
        .collect();
    let ca_types = tsl
        .tsl
        .services
        .iter()
        .filter(|s| s.service_type == crate::tsl::SERVICE_TYPE_CA_PKC)
        .filter_map(|s| Some((s.certificate.clone()?, s.type_oids.clone())))
        .collect();
    Ok(Verified {
        roots,
        intermediates: matched.intermediates,
        tsl_next_update: tsl.tsl.next_update,
        ocsp_responders,
        ca_types,
        tsl: Some(tsl),
        sequence,
    })
}

/// A list without its signature file is not material (TSLDET-013).
#[cfg(feature = "brainpool")]
fn verify_tsl(
    config: &TrustConfig,
    xml: &[u8],
    files: Option<DetachedTsl<'_>>,
    now: Timestamp,
) -> Result<VerifiedTsl, VerifyError> {
    let files = files.ok_or_else(|| {
        VerifyError::new("the TSL came without its detached signature (TSLDET-013)")
    })?;
    Ok(crate::tsl::Tsl::parse_verified_with_status(
        xml, files, config, now,
    )?)
}

/// Every TSL is signed on brainpoolP256r1 (TSLDET-004): without the curve none verifies.
#[cfg(not(feature = "brainpool"))]
fn verify_tsl(
    _: &TrustConfig,
    _: &[u8],
    _: Option<DetachedTsl<'_>>,
    _: Timestamp,
) -> Result<VerifiedTsl, VerifyError> {
    Err(VerifyError::new(
        "the TSL is signed on brainpoolP256r1, which needs the brainpool feature",
    ))
}

#[cfg(all(test, feature = "brainpool"))]
mod tests {
    use super::*;
    use crate::load::Detached;

    fn meta() -> super::super::Meta {
        super::super::Meta {
            etag: None,
            last_modified: None,
            fetched_at: Timestamp(0),
            max_age: None,
            source: super::super::Source::Embedded,
        }
    }

    /// The published PU set and the time it was captured at.
    fn prod_material(config: &TrustConfig) -> (TrustMaterial, Timestamp) {
        let read = |suffix: &str| {
            std::fs::read(format!(
                "{}/../../spec/tsl-detached/testdata/prod/ECC-RSA_TSL.{suffix}",
                env!("CARGO_MANIFEST_DIR")
            ))
            .unwrap()
        };
        let material = TrustMaterial::new(config.roots.to_vec(), meta(), read("xml"), meta())
            .with_detached(Some(Detached {
                signature: read("sig"),
                signature_meta: meta(),
                signer_status: None,
            }));
        (
            material,
            Timestamp::parse_rfc3339("2026-11-01T16:47:42Z").unwrap(),
        )
    }

    #[test]
    fn embedded_prod_material_verifies() {
        let config = TrustConfig::preset_prod();
        let (material, now) = prod_material(&config);
        let verified = verify_material(&config, &material, now, None).unwrap();
        assert_eq!(verified.roots.len(), 10);
        assert_eq!(verified.intermediates.len(), 71);
        assert_eq!(verified.ocsp_responders.len(), 95);
        assert_eq!(
            verified.tsl_next_update.map(|t| t.to_string()).as_deref(),
            Some("2026-11-27T00:00:07Z")
        );

        let broken = TrustMaterial {
            tsl: b"<html/>".to_vec(),
            ..material
        };
        let error = verify_material(&config, &broken, now, None).unwrap_err();
        assert!(error.reason.contains("TSL"), "{error}");
    }

    /// TSLDET-013: a list without its signature file is not material.
    #[test]
    fn tsldet_013_a_list_without_its_signature_does_not_verify() {
        let config = TrustConfig::preset_prod();
        let (material, now) = prod_material(&config);
        let unsigned = TrustMaterial {
            detached: None,
            ..material
        };
        let error = verify_material(&config, &unsigned, now, None).unwrap_err();
        assert!(error.reason.contains("TSLDET-013"), "{error}");
    }

    /// Material with its detached files verifies through them, status included.
    #[cfg(feature = "dangerous-nonprod")]
    #[test]
    fn tsldet_020_verify_material_adopts_the_supplied_status() {
        let base = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../spec/tsl-detached/testdata/ref/ECC-RSA_TSL-ref."
        );
        let read = |suffix: &str| std::fs::read(format!("{base}{suffix}")).unwrap();
        let config = TrustConfig::preset(crate::Env::Ref);
        let meta = super::super::Meta {
            etag: None,
            last_modified: None,
            fetched_at: Timestamp(0),
            max_age: None,
            source: super::super::Source::Embedded,
        };
        let material = TrustMaterial::new(
            config.roots.to_vec(),
            meta.clone(),
            read("xml"),
            meta.clone(),
        )
        .with_detached(Some(Detached {
            signature: read("sig"),
            signature_meta: meta.clone(),
            signer_status: Some((read("ocsp"), meta)),
        }));
        let captured_at = Timestamp::parse_rfc3339("2026-11-01T16:47:42Z").unwrap();
        let verified = verify_material(&config, &material, captured_at, None).unwrap();
        let tsl = verified.tsl.unwrap();
        assert!(
            tsl.signer_status.is_some(),
            "the supplied status was adopted"
        );
        assert!(
            !tsl.warnings
                .iter()
                .any(|w| w.code == crate::tsl_signature::TslCode::NoOcspCheck)
        );
    }

    /// Without brainpool no TSL verifies, and a TSL that does not verify fails the load: a
    /// caller that wants roots without the TSL loads them alone.
    #[test]
    fn without_brainpool_the_material_does_not_load() {
        let config = TrustConfig {
            algorithms: std::borrow::Cow::Borrowed(crate::algorithms::NIST),
            ..TrustConfig::preset_prod()
        };
        let (material, now) = prod_material(&config);
        let error = verify_material(&config, &material, now, None).unwrap_err();
        assert_eq!(
            error.tsl.map(|e| e.rule),
            Some("TSLDET-002"),
            "{}",
            error.reason
        );
    }
}
