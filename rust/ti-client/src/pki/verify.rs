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

//! A certificate validated the way a relying party would: the chain to the TI roots
//! through the TSL's CAs, under a profile, with OCSP. Offline, cached or embedded trust
//! material is used and revocation is skipped, and the result says so rather than
//! passing silently.

use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;
use ti_pki::ocsp::{DEFAULT_MAX_RESPONSE_AGE, OcspChecker};
use ti_pki::profile::{self, SelectReason};
use ti_pki::revocation::{ResponderAuthorization, RevocationMode, RevocationResult, Unchecked};
use ti_pki::trustdomain::detect_trust_domain;
use ti_pki::{
    Certificate, ChainPosition, Env, Tier, Timestamp, TrustConfig, TrustStore, ValidationResult,
    Validator, detect_certificate_type,
};

use super::inspect::{self, CertificateInfo};
use crate::block_on;
use crate::client::Client;
use crate::error::Error;
use crate::files::Dirs;
use crate::input::Loaded;
use crate::trust::{Session, TrustInfo, Warning};

/// The profile to validate under.
#[derive(Clone, Copy, Debug)]
pub enum ProfileChoice {
    /// The one the end entity's type and roles select, else the chain only.
    Auto,
    /// None: the chain only.
    ChainOnly,
    /// This one, whatever the certificate says.
    Forced(&'static profile::Profile),
}

/// What to validate, and how.
#[derive(Clone, Debug)]
pub struct Request {
    /// Where the certificates came from, e.g. the file or `host:port`.
    pub source: String,
    /// The end entity first, then any certificates that may help build its chain.
    pub certificates: Vec<Certificate>,
    /// The environment; `None` asks the certificates ([`environment`]).
    pub env: Option<Env>,
    /// The instant to validate at; `None` is now.
    pub at: Option<Timestamp>,
    /// No request is made: cached or embedded trust material, no OCSP.
    pub offline: bool,
    /// Validated as a client without brainpool would.
    pub nist_only: bool,
    /// The profile.
    pub profile: ProfileChoice,
    /// The name a server's certificate must carry.
    pub expected_fqdn: Option<String>,
    /// Where every OCSP request of the chain goes instead of each certificate's responder.
    pub ocsp_responder: Option<String>,
    /// How old an OCSP response may be; ti-pki's default when `None`.
    pub ocsp_max_age: Option<Duration>,
}

/// Whether the reference time is now or given: OCSP still answers for the time of the
/// query.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reference {
    /// Now.
    Now,
    /// A time the caller gave.
    Given,
}

/// The outcome of [`verify`].
#[derive(Serialize)]
pub struct Verification {
    /// [`Request::source`].
    pub source: String,
    /// The verdict.
    pub valid: bool,
    /// The environment validated in.
    pub environment: EnvironmentInfo,
    /// The instant validated at, RFC 3339.
    pub at: String,
    /// [`Verification::at`] as a timestamp.
    #[serde(skip)]
    pub at_ts: Timestamp,
    /// Whether [`Verification::at`] is now or was given.
    #[serde(skip)]
    pub reference: Reference,
    /// The end entity's gemSpec_PKI type, e.g. `C.HCI.AUT`.
    pub certificate_type: Option<String>,
    /// The profile validated under.
    pub profile: ProfileInfo,
    /// The trust material.
    pub trust: TrustInfo,
    /// False offline or with revocation disabled; the verdict then says nothing about
    /// revocation.
    pub revocation_checked: bool,
    /// `hard-fail`, `soft-fail` or `disabled`.
    pub revocation_mode: &'static str,
    /// TLS certificates of downloads were not checked ([`crate::Net::insecure`]).
    pub insecure_transport: bool,
    /// The OCSP settings given; absent with the defaults.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ocsp: Option<OcspSettings>,
    /// The chain, end entity first.
    pub chain: Vec<ChainEntry>,
    /// What made the certificate invalid.
    pub errors: Vec<Finding>,
    /// What did not affect the verdict.
    pub warnings: Vec<Finding>,
    /// The end entity as [`inspect`] describes it, at the instant validated at.
    #[serde(skip)]
    pub details: CertificateInfo,
    /// ti-pki's result, for a view of the chain.
    #[serde(skip)]
    pub result: ValidationResult,
}

/// The environment validated in.
#[derive(Serialize)]
pub struct EnvironmentInfo {
    /// E.g. `ref`.
    pub name: &'static str,
    /// Whether it is production.
    pub production: bool,
    /// How it was detected; absent when it was given.
    pub detection: Option<Detection>,
}

/// How the environment was told from the certificates.
#[derive(Serialize)]
pub struct Detection {
    /// The method that decided, e.g. `markers`.
    pub method: &'static str,
    /// What it found, for humans.
    pub detail: String,
}

/// The profile validated under.
#[derive(Serialize)]
pub struct ProfileInfo {
    /// The profile validated against; `None` checks the chain only.
    pub name: Option<&'static str>,
    /// `cert`, `default`, `forced`, `ambiguous`, `none` or `disabled`.
    pub reason: &'static str,
    /// Why, for humans; may be empty.
    pub detail: String,
}

/// OCSP settings other than the defaults.
#[derive(Serialize)]
pub struct OcspSettings {
    /// Where every request of the chain went; absent: each certificate's own responder.
    pub responder_url: Option<String>,
    /// How old a response may be.
    pub max_response_age_ms: u64,
}

/// A certificate of the chain.
#[derive(Serialize)]
pub struct ChainEntry {
    /// Its place: `end_entity`, `sub_ca`, `root`, ….
    pub position: &'static str,
    /// Its subject.
    pub subject: String,
    /// Its subject's common name.
    pub common_name: String,
    /// Its `notAfter`, RFC 3339.
    pub not_after: String,
    /// What OCSP said; absent when not asked (offline, the root, or not reached).
    pub revocation: Option<RevocationEntry>,
    /// The certificate.
    pub pem: String,
}

/// What OCSP said of a certificate.
#[derive(Serialize)]
pub struct RevocationEntry {
    /// `good`, `revoked` or `unknown`.
    pub status: &'static str,
    /// Revocation reason, or why the status is unknown.
    pub reason: String,
    /// The responder asked.
    pub responder_url: String,
    /// Common name of the response's signer.
    pub responder: String,
    /// `issuer`, `delegate`, `tsl_listed` or `same_tsp_delegate`; absent without a verified
    /// response.
    pub authorization: Option<&'static str>,
    /// The response's `producedAt`.
    pub produced_at: Option<String>,
    /// When the certificate was revoked.
    pub revoked_at: Option<String>,
    /// The response came from the cache (an earlier run, within the hour and its
    /// `nextUpdate`) and was verified again, not asked for now.
    pub cached: bool,
}

/// An error or warning of the validation.
#[derive(Serialize)]
pub struct Finding {
    /// Its stable code, e.g. `chain_incomplete`.
    pub code: String,
    /// Common name of the certificate concerned; empty when not tied to one.
    pub subject: String,
    /// What it means, for humans.
    pub message: String,
}

/// Validates `request.certificates` in `request.env` (or the one they show) against
/// trust material loaded through a session over `client` and `dirs`; `warn` hears what the
/// session tells as it opens. The client's observer hears which trust material was used.
///
/// # Errors
///
/// [`Error::EnvironmentUndetected`] when the environment is to be detected and cannot
/// be; the errors of [`Session::new`] and [`Session::load_env`]; [`Error::Certificate`]
/// when the chain cannot be validated at all.
pub fn verify(
    client: &Client,
    dirs: &Dirs,
    request: &Request,
    warn: impl Fn(Warning),
) -> Result<Verification, Error> {
    let certs = &request.certificates;
    let at = request.at.unwrap_or_else(Timestamp::now);
    let (env, detection) = environment(request.env, certs, at)?;
    let session = Session::new(client, dirs, request.offline, warn)?;
    let (config, material) = session.load_env(env, request.nist_only, request.at)?;
    session.observe(format_args!(
        "{env}: {} roots, {} TSL CAs from {}",
        material.info.roots, material.info.intermediates, material.info.source
    ));

    let mut warnings = Vec::new();
    let (mut validator, profile) = validator(
        request.profile,
        &config,
        material.store,
        &certs[0],
        &mut warnings,
    );
    validator.expected_fqdn.clone_from(&request.expected_fqdn);
    let validated = block_on(async {
        if let Some(transport) = session.transport() {
            let mut checker =
                OcspChecker::new(&config, transport, Timestamp::now).with_store(session.store());
            if let Some(url) = &request.ocsp_responder {
                checker = checker.with_responder_url(url.clone());
            }
            if let Some(age) = request.ocsp_max_age {
                checker = checker.with_max_response_age(age);
            }
            validator.validate(certs, at, &checker).await
        } else {
            // No OCSP offline. Set here, after the profile: config.validate rejects
            // Disabled under Prod, so this is the one place the relaxation happens, and
            // the result states it.
            validator.revocation = RevocationMode::Disabled;
            validator.validate(certs, at, &Unchecked).await
        }
    });
    let result = validated.map_err(|source| Error::Certificate {
        source_name: request.source.clone(),
        source,
    })?;

    let details = inspect::describe(&Loaded::without_key(certs[0].clone()), at);
    warnings.extend(result.warnings.iter().map(|w| Finding {
        code: w.code.to_string(),
        subject: w.subject.clone(),
        message: w.message.clone(),
    }));
    Ok(Verification {
        source: request.source.clone(),
        valid: result.valid,
        environment: EnvironmentInfo {
            name: env.as_str(),
            production: env.is_prod(),
            detection,
        },
        at: at.to_string(),
        at_ts: at,
        reference: if request.at.is_some() {
            Reference::Given
        } else {
            Reference::Now
        },
        certificate_type: detect_certificate_type(&certs[0]).map(|t| t.to_string()),
        profile,
        trust: material.info,
        revocation_checked: !request.offline && validator.revocation != RevocationMode::Disabled,
        revocation_mode: mode_name(validator.revocation),
        insecure_transport: session.insecure,
        ocsp: ocsp_settings(request),
        chain: chain(&result),
        errors: result
            .errors
            .iter()
            .map(|e| Finding {
                code: e.code.to_string(),
                subject: e.subject.clone(),
                message: e.message.clone(),
            })
            .collect(),
        warnings,
        details,
        result,
    })
}

/// The OCSP settings `request` gives; none with the defaults.
fn ocsp_settings(request: &Request) -> Option<OcspSettings> {
    (request.ocsp_responder.is_some() || request.ocsp_max_age.is_some()).then(|| OcspSettings {
        responder_url: request.ocsp_responder.clone(),
        max_response_age_ms: u64::try_from(
            request
                .ocsp_max_age
                .unwrap_or(DEFAULT_MAX_RESPONSE_AGE)
                .as_millis(),
        )
        .unwrap_or(u64::MAX),
    })
}

fn chain(result: &ValidationResult) -> Vec<ChainEntry> {
    result
        .chain
        .iter()
        .zip(&result.positions)
        .enumerate()
        .map(|(i, (cert, position))| ChainEntry {
            position: position.as_str(),
            subject: cert.subject().to_string(),
            common_name: cert.subject_cn().to_owned(),
            not_after: cert.not_after().to_string(),
            revocation: result
                .cert_results
                .get(i)
                .and_then(|r| r.revocation.as_ref())
                .map(revocation_entry),
            pem: cert.to_pem(),
        })
        .collect()
}

impl Verification {
    /// Whether the chain reaches a root.
    pub fn complete(&self) -> bool {
        self.result.positions.last() == Some(&ChainPosition::Root)
    }
}

/// The environment to validate in; `None` asks the certificates. Non-production evidence
/// maps to ref: ref and test share their roots, so the choice only matters once the TSL
/// and OCSP come into play.
///
/// # Errors
///
/// [`Error::EnvironmentUndetected`] with each method tried and its outcome.
pub fn environment(
    choice: Option<Env>,
    certs: &[Certificate],
    at: Timestamp,
) -> Result<(Env, Option<Detection>), Error> {
    if let Some(env) = choice {
        return Ok((env, None));
    }
    let found = detect_trust_domain(certs, at);
    let (Some(tier), Some(method)) = (found.domain, found.method) else {
        let tried: Vec<String> = found
            .steps
            .iter()
            .map(|step| format!("{}: {}", step.method, step.outcome))
            .collect();
        return Err(Error::EnvironmentUndetected(tried.join("; ")));
    };
    let env = match tier {
        Tier::Prod => Env::Prod,
        Tier::NonProd => Env::Ref,
    };
    Ok((
        env,
        Some(Detection {
            method: method.as_str(),
            detail: found.detail,
        }),
    ))
}

fn validator(
    choice: ProfileChoice,
    config: &TrustConfig,
    store: Arc<TrustStore>,
    ee: &Certificate,
    warnings: &mut Vec<Finding>,
) -> (Validator, ProfileInfo) {
    let chain_only = |reason, detail: String| ProfileInfo {
        name: None,
        reason,
        detail,
    };
    let p = match choice {
        ProfileChoice::ChainOnly => {
            return (
                Validator::new(config, store),
                chain_only("disabled", "chain only, as requested".into()),
            );
        }
        ProfileChoice::Auto => {
            let selection = profile::select_for_cert(ee);
            let (Some(p), Some(t)) = (selection.profile, selection.cert_type) else {
                let code = if selection.reason == SelectReason::Ambiguous {
                    "profile_ambiguous"
                } else {
                    "profile_not_detected"
                };
                warnings.push(Finding {
                    code: code.into(),
                    subject: ee.subject_cn().to_owned(),
                    message: format!("{}; checked the chain only", selection.detail),
                });
                return (
                    Validator::new(config, store),
                    chain_only(selection.reason.as_str(), selection.detail),
                );
            };
            return (
                p.validator(config, store, t),
                ProfileInfo {
                    name: Some(p.name),
                    reason: selection.reason.as_str(),
                    detail: selection.detail,
                },
            );
        }
        ProfileChoice::Forced(p) => p,
    };
    let forced = |detail: String| ProfileInfo {
        name: Some(p.name),
        reason: "forced",
        detail,
    };
    let Some(t) = detect_certificate_type(ee) else {
        let validator = Validator {
            required_role_oids: p.required_role_oids.to_vec(),
            accepted_types: p.accepts_types.to_vec(),
            revocation: p.revocation_mode(config),
            ..Validator::new(config, store)
        };
        return (
            validator,
            forced("type not detected; checked the profile's roles only".into()),
        );
    };
    (p.validator(config, store, t), forced(String::new()))
}

fn revocation_entry(r: &RevocationResult) -> RevocationEntry {
    RevocationEntry {
        status: r.status.as_str(),
        reason: r.reason.clone(),
        responder_url: r.responder_url.clone(),
        responder: r.responder_name.clone(),
        authorization: r.authorization.as_ref().map(|a| match a {
            ResponderAuthorization::Issuer => "issuer",
            ResponderAuthorization::Delegate => "delegate",
            ResponderAuthorization::TslListed { .. } => "tsl_listed",
            ResponderAuthorization::SameTspDelegate { .. } => "same_tsp_delegate",
            _ => "other",
        }),
        produced_at: r.produced_at.map(|t| t.to_string()),
        revoked_at: r.revoked_at.map(|t| t.to_string()),
        cached: r.from_cache,
    }
}

/// The name of `mode` as [`Verification::revocation_mode`] gives it.
pub fn mode_name(mode: RevocationMode) -> &'static str {
    match mode {
        RevocationMode::HardFail => "hard-fail",
        RevocationMode::SoftFail => "soft-fail",
        RevocationMode::Disabled => "disabled",
    }
}
