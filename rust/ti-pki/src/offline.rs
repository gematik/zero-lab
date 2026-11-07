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

use std::sync::Arc;

use core::pin::pin;
use core::task::{Context, Poll, Waker};

use crate::cert_type::CertificateType;
use crate::load::VerifyError;
use crate::profile::{Profile, SelectReason, select_for_cert};
use crate::revocation::{RevocationMode, Unchecked};
use crate::tsl_signature::{DetachedTsl, VerifiedTsl};
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

/// Runs the async validation without a runtime: with revocation unchecked nothing in it
/// waits, so the future is complete when first polled.
fn block_on<F: Future>(future: F) -> F::Output {
    match pin!(future).poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(output) => output,
        Poll::Pending => unreachable!("validation without revocation never waits"),
    }
}
