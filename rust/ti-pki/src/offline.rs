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

//! A certificate checked against an environment's TSL and roots that the caller holds
//! already, without a network: what `ti pki verify --profile auto --offline` decides, for
//! a host that cannot fetch, such as a browser.
//!
//! [`Check::new`] verifies the trust material once; [`Check::check`] then judges any
//! number of certificates against it. Revocation is never checked: OCSP needs a network.
//!
//! [`Tsl::verify`] verifies a TSL for one environment the same way and matches its CAs and
//! every service certificate to the verified roots, for a host that shows the list.

#[cfg(feature = "brainpool")]
use std::borrow::Cow;
use std::sync::Arc;

use core::pin::pin;
use core::task::{Context, Poll, Waker};

use crate::cert_type::CertificateType;
use crate::load::VerifyError;
use crate::profile::{Profile, SelectReason, select_for_cert};
use crate::revocation::{RevocationMode, Unchecked};
use crate::tsl::{Matched, Rejection};
#[cfg(feature = "brainpool")]
use crate::tsl_signature::TslCode;
use crate::tsl_signature::{DetachedTsl, TslError, VerifiedTsl};
use crate::{
    Certificate, Env, Error, Timestamp, TrustConfig, TrustStore, ValidationResult, Validator,
};

/// Which roots.json the trust material was verified with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RootsSource {
    /// The caller's, which walked from the anchor.
    Supplied,
    /// The one `TrustConfig::roots` holds.
    Embedded,
}

/// The trust material of one environment, as verified.
#[derive(Clone, Debug)]
pub struct Material {
    /// The roots the TSL's CAs were matched against; [`RootsSource::Embedded`] as well
    /// when nothing verified, since nothing is used then.
    pub roots_source: RootsSource,
    /// Why the supplied roots.json was not used.
    pub roots_warning: Option<String>,
    /// The verified list, or why the list or the roots were rejected; nothing is trusted
    /// from a rejected list.
    pub tsl: Result<VerifiedTsl, VerifyError>,
}

/// The profile a certificate was checked under.
#[derive(Clone, Debug)]
pub enum ProfileChoice {
    /// The profile [`select_for_cert`] picked, for the type it detected.
    Detected {
        /// The profile.
        profile: &'static Profile,
        /// The certificate's Tab_PKI_405 type.
        cert_type: CertificateType,
        /// How it was chosen.
        reason: SelectReason,
        /// Why, for humans.
        detail: String,
    },
    /// No profile applies, for the reason in `detail`: only the chain was checked.
    ChainOnly {
        /// Why no profile applies, for humans.
        detail: String,
    },
}

/// What a check found.
#[derive(Debug)]
pub enum Outcome {
    /// The trust material did not verify: nothing is trusted, so nothing was validated.
    Untrusted,
    /// The certificate was validated with revocation disabled.
    Validated {
        /// The profile it was validated under.
        profile: ProfileChoice,
        /// The validation; an error when the input could not be validated at all.
        result: Result<ValidationResult, Error>,
    },
}

/// The trust material of one environment, verified, ready to check certificates against.
pub struct Check {
    env: Env,
    config: TrustConfig,
    store: Option<Arc<TrustStore>>,
    material: Material,
}

impl Check {
    /// Verifies the TSL `tsl_xml` by its detached signature `tsl_signature` for `env`
    /// under `config` at `now`, with the roots of `supplied_roots` if that roots.json walks
    /// from the anchor, else with `config.roots`. A rejected list is not an error: every
    /// check against it is [`Outcome::Untrusted`].
    ///
    /// The anchored walk cannot add a root the anchor does not reach (A_28419), so
    /// supplied roots never widen trust.
    pub fn new(
        env: Env,
        config: TrustConfig,
        supplied_roots: Option<&[u8]>,
        tsl_xml: &[u8],
        tsl_signature: &[u8],
        now: Timestamp,
    ) -> Self {
        let mut roots_warning = None;
        let files = DetachedTsl {
            signature: tsl_signature,
            signer_status: None,
        };
        let attempt = |roots: &[u8]| TrustStore::from_material(&config, roots, tsl_xml, files, now);
        let outcome = match supplied_roots {
            Some(json) => match attempt(json) {
                // A TSL that fails fails with any roots; only a roots failure falls back.
                Err(e) if e.tsl.is_none() => {
                    roots_warning = Some(format!("supplied roots.json: {e}"));
                    attempt(&config.roots).map(|ok| (ok, RootsSource::Embedded))
                }
                other => other.map(|ok| (ok, RootsSource::Supplied)),
            },
            None => attempt(&config.roots).map(|ok| (ok, RootsSource::Embedded)),
        };
        let (store, material) = match outcome {
            Ok(((store, verified), roots_source)) => (
                Some(Arc::new(store)),
                Material {
                    roots_source,
                    roots_warning,
                    tsl: Ok(verified),
                },
            ),
            Err(e) => (
                None,
                Material {
                    roots_source: RootsSource::Embedded,
                    roots_warning,
                    tsl: Err(e),
                },
            ),
        };
        Check {
            env,
            config,
            store,
            material,
        }
    }

    /// The environment checked against.
    pub fn env(&self) -> Env {
        self.env
    }

    /// The trust material.
    pub fn material(&self) -> &Material {
        &self.material
    }

    /// `certs`, the end entity first and any intermediates after it, validated at `now`
    /// under the profile picked for the end entity, or as a chain only when none applies.
    ///
    /// # Panics
    ///
    /// If `certs` is empty.
    pub fn check(&self, certs: &[Certificate], now: Timestamp) -> Outcome {
        let ee = &certs[0];
        let Some(store) = &self.store else {
            return Outcome::Untrusted;
        };
        let selection = select_for_cert(ee);
        let (profile, mut validator) =
            if let (Some(profile), Some(cert_type)) = (selection.profile, selection.cert_type) {
                let validator = profile.validator(&self.config, Arc::clone(store), cert_type);
                let choice = ProfileChoice::Detected {
                    profile,
                    cert_type,
                    reason: selection.reason,
                    detail: selection.detail,
                };
                (choice, validator)
            } else {
                let choice = ProfileChoice::ChainOnly {
                    detail: selection.detail,
                };
                (choice, Validator::new(&self.config, Arc::clone(store)))
            };
        validator.revocation = RevocationMode::Disabled;
        let result = block_on(validator.validate(certs, now, &Unchecked));
        Outcome::Validated { profile, result }
    }
}

/// A TSL verified for one environment, with its CAs and service certificates matched to
/// the verified roots.
#[derive(Clone, Debug)]
pub struct Tsl {
    /// The list, its signer and the signer's CA.
    pub verified: VerifiedTsl,
    /// The roots the CAs were matched against, the anchor first, then in walk order.
    pub roots: Vec<Certificate>,
    /// Which roots.json they came from.
    pub roots_source: RootsSource,
    /// Why the supplied roots.json was not used.
    pub roots_warning: Option<String>,
    /// The list's CA candidates, split by whether a root signed them.
    pub matched: Matched,
    /// The kept CAs, each with the root that signed it, in list order.
    pub kept: Vec<SignedCa>,
    /// For each service of the list, in list order: the chain of its certificate, for a
    /// service in accord that has one.
    pub chains: Vec<Option<ServiceChain>>,
}

/// A CA of the list a verified root signed, with that root.
#[derive(Clone, Debug)]
pub struct SignedCa {
    /// The CA.
    pub ca: Certificate,
    /// The root that signed it.
    pub root: Certificate,
}

/// The chain from a service certificate towards a verified root.
#[derive(Clone, Debug)]
pub struct ServiceChain {
    /// The certificates, the service's first, as far as the chain was built.
    pub path: Vec<Certificate>,
    /// Why it does not end in a verified root; `None` when it does.
    pub rejection: Option<Rejection>,
}

/// Why a TSL cannot be used.
#[derive(Clone, Debug)]
pub enum TslFailure {
    /// The list, its signature or its signer was rejected, or it is signed for the other
    /// tier.
    Tsl(TslError),
    /// No roots verified, not even the embedded ones.
    Roots(String),
}

impl Tsl {
    /// Verifies `xml` by its detached `files` as the TSL of `env` under `config` at
    /// `now`, and matches it to the roots of `supplied_roots` if that roots.json walks
    /// from the anchor of `config` at `now`, to those of `config.roots` otherwise. The
    /// anchored walk cannot add a root the anchor does not reach (A_28419), so supplied
    /// roots never widen trust. `config` should have passed [`TrustConfig::validate`]
    /// for the tier of `env`.
    ///
    /// # Errors
    ///
    /// [`TslFailure`]: nothing from the list may be used.
    #[cfg(feature = "brainpool")]
    pub fn verify(
        xml: &[u8],
        files: DetachedTsl<'_>,
        env: Env,
        config: &TrustConfig,
        supplied_roots: Option<&[u8]>,
        now: Timestamp,
    ) -> Result<Self, TslFailure> {
        let verified = crate::tsl::Tsl::parse_verified_with_status(xml, files, config, now)
            .map_err(TslFailure::Tsl)?;
        // The presets keep the tiers apart already; this holds even for a hand-built config.
        if verified.tier != env.tier() {
            return Err(TslFailure::Tsl(TslError {
                code: TslCode::CertificateNotValidMath,
                rule: "TSLSIG-031",
                detail: format!(
                    "the list is signed for {}, not for {}",
                    verified.tier.as_str(),
                    env.as_str()
                ),
            }));
        }
        let (roots, roots_source, roots_warning) =
            load_roots(config, supplied_roots, now).map_err(TslFailure::Roots)?;
        let store = TrustStore::new(roots.iter().cloned());
        let matched =
            crate::tsl::match_to_roots(verified.tsl.intermediate_cas(), &store, &config.algorithms);
        // Each kept CA with its root, found once: signature checks dominate the time.
        let kept: Vec<SignedCa> = matched
            .intermediates
            .iter()
            .filter_map(|i| {
                let root = issuing_root(&i.certificate, &store, config)?;
                Some(SignedCa {
                    ca: i.certificate.clone(),
                    root: root.clone(),
                })
            })
            .collect();
        let chains = verified
            .tsl
            .services
            .iter()
            .map(|service| service_chain(service, &store, &kept, &matched.rejected, config))
            .collect();
        Ok(Tsl {
            verified,
            roots,
            roots_source,
            roots_warning,
            matched,
            kept,
            chains,
        })
    }
}

#[cfg(feature = "brainpool")]
fn load_roots(
    config: &TrustConfig,
    supplied: Option<&[u8]>,
    now: Timestamp,
) -> Result<(Vec<Certificate>, RootsSource, Option<String>), String> {
    let mut warning = None;
    if let Some(json) = supplied {
        let with_supplied = TrustConfig {
            roots: Cow::Owned(json.to_vec()),
            ..config.clone()
        };
        match crate::roots::load(&with_supplied, now) {
            Ok(walk) => return Ok((walk.trusted, RootsSource::Supplied, None)),
            Err(e) => warning = Some(format!("supplied roots.json: {e}")),
        }
    }
    let walk = crate::roots::load(config, now).map_err(|e| format!("embedded roots.json: {e}"))?;
    Ok((walk.trusted, RootsSource::Embedded, warning))
}

#[cfg(feature = "brainpool")]
/// The chain of a service in accord with a certificate.
fn service_chain(
    service: &crate::tsl::Service,
    store: &TrustStore,
    kept: &[SignedCa],
    rejected: &[(crate::tsl::Intermediate, Rejection)],
    config: &TrustConfig,
) -> Option<ServiceChain> {
    let cert = service.certificate.as_ref()?;
    service
        .is_in_accord()
        .then(|| chain(cert, store, kept, rejected, config))
}

#[cfg(feature = "brainpool")]
/// The path from `cert` up to a verified root: a CA the roots kept goes straight to its
/// root, any other certificate through the kept CA that signed it, or a root.
fn chain(
    cert: &Certificate,
    store: &TrustStore,
    kept: &[SignedCa],
    rejected: &[(crate::tsl::Intermediate, Rejection)],
    config: &TrustConfig,
) -> ServiceChain {
    let ends =
        |path: Vec<Certificate>, rejection: Option<Rejection>| ServiceChain { path, rejection };
    let mut path = vec![cert.clone()];
    if store.contains(cert) {
        return ends(path, None);
    }
    if let Some((_, reason)) = rejected.iter().find(|(i, _)| &i.certificate == cert) {
        return ends(path, Some(*reason));
    }
    if let Some(k) = kept.iter().find(|k| &k.ca == cert) {
        path.push(k.root.clone());
        return ends(path, None);
    }
    if let Some(k) = kept.iter().find(|k| signed_by(cert, &k.ca, config)) {
        path.push(k.ca.clone());
        path.push(k.root.clone());
        return ends(path, None);
    }
    if let Some(root) = issuing_root(cert, store, config) {
        path.push(root.clone());
        return ends(path, None);
    }
    let named = kept.iter().any(|k| k.ca.subject_der() == cert.issuer_der());
    let reason = if named {
        Rejection::BadSignature
    } else {
        Rejection::UnknownIssuer
    };
    ends(path, Some(reason))
}

#[cfg(feature = "brainpool")]
fn issuing_root<'s>(
    cert: &Certificate,
    store: &'s TrustStore,
    config: &TrustConfig,
) -> Option<&'s Certificate> {
    store
        .roots()
        .iter()
        .find(|root| signed_by(cert, root, config))
}

#[cfg(feature = "brainpool")]
fn signed_by(cert: &Certificate, issuer: &Certificate, config: &TrustConfig) -> bool {
    cert.issuer_der() == issuer.subject_der()
        && cert.verify_signed_by(issuer, &config.algorithms).is_ok()
}

/// Runs the async validation without a runtime: with revocation unchecked nothing in it
/// waits, so the future is complete when first polled.
fn block_on<F: Future>(future: F) -> F::Output {
    match pin!(future).poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(output) => output,
        Poll::Pending => unreachable!("validation without revocation never waits"),
    }
}
