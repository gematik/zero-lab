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

//! The TSL of an environment: its CAs under the verified roots that signed them, and the
//! ones no verified root signed. The list is read from its signed bytes once its
//! signature, signer and `NextUpdate` verified (`spec/tsl-detached`); a CA still counts
//! only if a verified root signed it, and what is said about a CA comes from its
//! certificate. And a TSL file verified on its own: its signature and signer under the
//! embedded TSL signer CA of an environment (`spec/tsl-detached`, `spec/tsl-xmldsig`
//! part B).

use std::time::Duration;

use der::asn1::ObjectIdentifier;
use serde::Serialize;
use ti_pki::load::{Detached, Meta, Source};
use ti_pki::model::{CertSummary, Finding, Oid, rejection_code};
use ti_pki::ocsp::OcspChecker;
use ti_pki::tsl::{self, Intermediate, Tsl};
use ti_pki::tsl_signature::{Sequence, TslError, TslState, VerifiedTsl, embedded_config_for};
use ti_pki::{Certificate, Env, Tier, Timestamp, TrustConfig, TrustStore};

use super::bundle::Found;
use super::roots::generation;
use crate::block_on;
use crate::error::Error;
use crate::file_cache::FileCache;
use crate::http::Http;
use crate::trust::{Material, Session, VerifiedSet};

/// The verified TSL of an environment and what its verified roots make of it.
pub struct Loaded {
    /// The environment.
    pub env: Env,
    /// Its configuration.
    pub config: TrustConfig,
    /// Its trust material.
    pub material: Material,
    /// The TSL as published, and verified.
    pub bytes: Vec<u8>,
    /// Where the TSL came from and when.
    pub meta: Meta,
    /// The files the list verified with.
    pub detached: Option<Detached>,
    /// The verified list.
    pub verified: VerifiedTsl,
    /// Its CAs, as the verified roots take them.
    pub matched: tsl::Matched,
    /// The instant it was verified at.
    pub now: Timestamp,
    /// Downloads skipped the TLS check ([`crate::Net::insecure`]).
    pub insecure: bool,
}

/// `env`'s TSL, verified at `at` or now. The roots first: they decide which of the TSL's
/// CAs count, and loading them refreshes the cached TSL too. The TSL is then read from its
/// signed bytes once it verified.
///
/// # Errors
///
/// [`Error::Trust`] for a preset its tier does not admit; those of [`Session::load`] and
/// [`Session::verified_set`].
pub fn load(session: &Session, env: Env, at: Option<Timestamp>) -> Result<Loaded, Error> {
    let config = TrustConfig::preset(env);
    config.validate(env.tier()).map_err(Error::Trust)?;
    let material = session.load(&config, env.tier(), at)?;
    let now = at.unwrap_or_else(Timestamp::now);
    let VerifiedSet { set, verified } = session.verified_set(&config, &material, at)?;
    let matched = tsl::match_to_roots(
        verified.tsl.intermediate_cas(),
        &TrustStore::new(material.store.roots().iter().cloned()),
        &config.algorithms,
    );
    Ok(Loaded {
        env,
        config,
        material,
        meta: set.meta[1].clone(),
        detached: set.detached,
        bytes: set.tsl,
        verified,
        matched,
        now,
        insecure: session.insecure,
    })
}

/// Which of the TSL's CAs to take: each list keeps a CA whose name contains any of its
/// texts, ignoring case, and an empty list keeps all.
#[derive(Clone, Debug, Default)]
pub struct CaFilter {
    /// By the CA's common name.
    pub ca: Vec<String>,
    /// By the provider's name.
    pub provider: Vec<String>,
    /// By the common name of the root that signed it.
    pub root: Vec<String>,
    /// By the certificate types the TSL lets it issue; case and `.` or `-` do not matter.
    pub issues: Vec<String>,
}

impl CaFilter {
    /// Whether `ca` passes [`CaFilter::ca`] and [`CaFilter::provider`].
    pub fn wants(&self, ca: &Intermediate) -> bool {
        contains(&self.ca, ca.certificate.subject_cn()) && contains(&self.provider, &ca.provider)
    }

    /// Whether a CA the TSL lets issue `types` passes [`CaFilter::issues`]; one it states no
    /// types for passes only without the filter.
    pub fn wants_types(&self, types: Option<&[ObjectIdentifier]>) -> bool {
        if self.issues.is_empty() {
            return true;
        }
        let fold = ti_pki::cert_type::fold_name;
        type_names(types).iter().any(|name| {
            let name = fold(name);
            self.issues.iter().any(|f| name.contains(&fold(f)))
        })
    }

    /// Whether `root` passes [`CaFilter::root`].
    pub fn wants_root(&self, root: &Certificate) -> bool {
        contains(&self.root, root.subject_cn())
    }

    /// Whether a filter on the CAs themselves is set.
    fn on_cas(&self) -> bool {
        !self.ca.is_empty() || !self.provider.is_empty() || !self.issues.is_empty()
    }
}

/// The TSL's CAs under the verified roots that signed them, and the rejected ones.
#[derive(Serialize)]
pub struct Overview {
    /// E.g. `prod`.
    pub environment: &'static str,
    /// Where the list came from.
    pub source: SourceInfo,
    /// Downloads skipped the TLS check.
    pub insecure_transport: bool,
    /// The C.TSL.SIG certificate the list is signed with.
    pub signer: String,
    /// The TSL signer CA that issued it.
    pub tsl_signer_ca: String,
    /// `no_ocsp_check`, `validity_warning_1`.
    pub warnings: Vec<&'static str>,
    /// `TSLSequenceNumber`.
    pub sequence_number: u64,
    /// `ListIssueDateTime`, RFC 3339.
    pub issued_at: String,
    /// [`Overview::issued_at`] as a timestamp.
    #[serde(skip)]
    pub issued_at_ts: Timestamp,
    /// `NextUpdate`, RFC 3339; none for a closed list.
    pub next_update: Option<String>,
    /// [`Overview::next_update`] as a timestamp.
    #[serde(skip)]
    pub next_update_ts: Option<Timestamp>,
    /// Past `next_update`: a newer list should exist.
    pub overdue: bool,
    /// Over the whole list, whatever the filters.
    pub counts: Counts,
    /// The verified roots with the CAs they signed, after the filters.
    pub roots: Vec<RootEntry>,
    /// The CAs no verified root signed, after the filters.
    pub rejected: Vec<CaInfo>,
    /// Whether filters left anything out.
    pub filtered: bool,
}

/// Where the list came from.
#[derive(Serialize)]
pub struct SourceInfo {
    /// `http` or `cache`.
    pub source: &'static str,
    /// When the TSL was downloaded or last confirmed.
    pub fetched_at: String,
    /// [`SourceInfo::fetched_at`] as a timestamp.
    #[serde(skip)]
    pub fetched_at_ts: Timestamp,
}

/// The list's CAs, counted.
#[derive(Serialize)]
pub struct Counts {
    /// CA services in accord with a certificate: the candidates.
    pub listed: usize,
    /// Signed by a verified root; these take part in chain building.
    pub kept: usize,
    /// Signed by no verified root.
    pub rejected: usize,
}

/// A verified root and the CAs it signed.
#[derive(Serialize)]
pub struct RootEntry {
    /// Its common name.
    pub common_name: String,
    /// Its `notAfter`, RFC 3339.
    pub not_after: String,
    /// `valid`, `expired` or `not_yet_valid`, at the instant verified at.
    pub validity: &'static str,
    /// The CAs it signed.
    pub cas: Vec<CaInfo>,
}

/// A CA of the list.
#[derive(Serialize)]
pub struct CaInfo {
    /// Its common name.
    pub common_name: String,
    /// Its subject.
    pub subject: String,
    /// Its issuer.
    pub issuer: String,
    /// The TSPName the TSL lists the CA under.
    pub provider: String,
    /// Its `notBefore`, RFC 3339.
    pub not_before: String,
    /// Its `notAfter`, RFC 3339.
    pub not_after: String,
    /// [`CaInfo::not_after`] as a timestamp.
    #[serde(skip)]
    pub not_after_at: Timestamp,
    /// `valid`, `expired` or `not_yet_valid`, now.
    pub validity: &'static str,
    /// The certificate policies the CA certificate asserts.
    pub policies: Vec<Oid>,
    /// The certificate's path length constraint.
    pub path_len: Option<u8>,
    /// For a CA the TSL lists as revoked, its `StatusStartingTime` (RFC 3339): end
    /// entities issued before stay valid, later ones do not. Null for a CA in accord.
    pub revoked_since: Option<String>,
    /// The certificate types the TSL lets it issue (`C.FD.TLS-S`, …); OIDs it names no
    /// type for appear as dotted strings. Empty when the TSL states none.
    pub issuable_types: Vec<String>,
    /// Why no verified root signed it: `not_ca`, `self_signed`, `unknown_issuer`,
    /// `bad_signature`; absent for kept CAs.
    pub rejection: Option<&'static str>,
    /// The SHA-256 fingerprint.
    pub sha256: String,
    /// The certificate.
    pub pem: String,
}

/// The CAs of `loaded` that pass `filter`, under their roots; with `rejected_only`, only
/// those no verified root signed.
pub fn overview(loaded: &Loaded, filter: &CaFilter, rejected_only: bool) -> Overview {
    let Loaded {
        env,
        material,
        meta,
        verified,
        matched,
        now,
        ..
    } = loaded;
    let now = *now;
    let list = &verified.tsl;
    let store = &material.store;
    let wanted = |ca: &Intermediate| {
        filter.wants(ca) && filter.wants_types(store.tsl_types_of(&ca.certificate))
    };
    let mut root_entries: Vec<RootEntry> = store
        .roots()
        .iter()
        .filter(|root| !rejected_only && filter.wants_root(root))
        .map(|root| RootEntry {
            common_name: root.subject_cn().to_owned(),
            not_after: root.not_after().to_string(),
            validity: ti_pki::model::validity(root, now),
            cas: matched
                .intermediates
                .iter()
                .filter(|ca| issued_by(&ca.certificate, root) && wanted(ca))
                .map(|ca| describe(ca, None, now, store))
                .collect(),
        })
        .collect();
    if filter.on_cas() {
        root_entries.retain(|root| !root.cas.is_empty());
    }
    let rejected: Vec<CaInfo> = matched
        .rejected
        .iter()
        .filter(|(ca, _)| filter.root.is_empty() && wanted(ca))
        .map(|(ca, reason)| describe(ca, Some(rejection_code(*reason)), now, store))
        .collect();
    Overview {
        environment: env.as_str(),
        source: SourceInfo {
            source: source_name(meta),
            fetched_at: meta.fetched_at.to_string(),
            fetched_at_ts: meta.fetched_at,
        },
        insecure_transport: loaded.insecure,
        signer: verified.signer.subject_cn().to_owned(),
        tsl_signer_ca: verified.anchor.subject_cn().to_owned(),
        warnings: material.info.tsl_warnings.clone(),
        sequence_number: list.sequence_number,
        issued_at: list.issued_at.to_string(),
        issued_at_ts: list.issued_at,
        next_update: list.next_update.map(|t| t.to_string()),
        next_update_ts: list.next_update,
        overdue: list.next_update.is_some_and(|next| now > next),
        counts: Counts {
            listed: matched.intermediates.len() + matched.rejected.len(),
            kept: matched.intermediates.len(),
            rejected: matched.rejected.len(),
        },
        roots: root_entries,
        rejected,
        filtered: rejected_only || filter.on_cas() || !filter.root.is_empty(),
    }
}

/// The CAs a bundle of `loaded` takes: those [`overview`] keeps under the verified roots
/// with `filter`, the rejected ones never; with `nist_only`, only those a client without
/// brainpool can use; with `issued` given, only those that issued one of them or are one
/// of them; with `with_roots`, their roots after them, oldest generation first. And the
/// certificates of `issued` whose issuer is neither a CA taken nor a root.
pub fn bundle(
    loaded: Loaded,
    filter: &CaFilter,
    nist_only: bool,
    with_roots: bool,
    issued: &[Certificate],
) -> (Found, Vec<Certificate>) {
    let usable = |cert: &Certificate| {
        !nist_only
            || ti_pki::algorithms::supports_key(ti_pki::algorithms::NIST, &cert.public_key_alg_id())
    };
    let store = &loaded.material.store;
    let roots = store.roots();
    // A CA counts when it issued one of the certificates, or is one of them (a chain
    // file, or a server that sends its CA).
    let issuer_wanted = |ca: &Certificate| {
        issued.is_empty()
            || issued
                .iter()
                .any(|cert| cert.issuer() == ca.subject() || cert.der() == ca.der())
    };
    let mut certificates: Vec<Certificate> = loaded
        .matched
        .intermediates
        .iter()
        // A bundle cannot carry the rule for revoked CAs (only what they issued before
        // their StatusStartingTime counts), so they stay out.
        .filter(|ca| ca.revoked_since.is_none())
        .filter(|ca| {
            filter.wants(ca)
                && filter.wants_types(store.tsl_types_of(&ca.certificate))
                && usable(&ca.certificate)
                && issuer_wanted(&ca.certificate)
                && roots
                    .iter()
                    .any(|root| issued_by(&ca.certificate, root) && filter.wants_root(root))
        })
        .map(|ca| ca.certificate.clone())
        .collect();
    let unknown = issued
        .iter()
        .filter(|cert| {
            !certificates
                .iter()
                .any(|ca| cert.issuer() == ca.subject() || cert.der() == ca.der())
                && !roots.iter().any(|root| cert.issuer() == root.subject())
        })
        .cloned()
        .collect();
    if with_roots {
        let mut chained: Vec<Certificate> = roots
            .iter()
            .filter(|root| usable(root) && certificates.iter().any(|ca| issued_by(ca, root)))
            .cloned()
            .collect();
        chained.sort_by_key(|root| generation(root.subject_cn()));
        certificates.extend(chained);
    }
    (
        Found {
            environment: loaded.env.as_str(),
            certificates,
            tsl_sequence_number: Some(loaded.verified.tsl.sequence_number),
            trust: loaded.material.info,
            insecure_transport: loaded.insecure,
        },
        unknown,
    )
}

/// A TSL file and what comes with it, to verify.
pub struct Files<'a> {
    /// The file's name, e.g. its path.
    pub source: String,
    /// The list as read.
    pub list: &'a [u8],
    /// Its detached signature.
    pub signature: &'a [u8],
    /// The signer's OCSP status published with it, if given.
    pub signer_status: Option<&'a [u8]>,
    /// A list it may not roll back behind, and its name.
    pub previous: Option<(&'a [u8], &'a str)>,
}

/// A TSL file's verification, as one document.
#[derive(Serialize)]
pub struct Verdict {
    /// [`Files::source`].
    pub source: String,
    /// The environment asked for, or `auto`.
    pub environment: &'static str,
    /// The validation time.
    pub at: String,
    /// `valid` or `invalid`.
    pub result: &'static str,
    /// `prod` or `nonprod`, from the TSL signer CA; valid lists only.
    pub tier: Option<&'static str>,
    /// The result code of an invalid list, e.g. `detached_signature_error`.
    pub code: Option<&'static str>,
    /// Its gemSpec_PKI Tab_PKI_274 number, if it has one.
    pub code_number: Option<u16>,
    /// The rule of `spec/tsl-detached` or `spec/tsl-xmldsig` that failed.
    pub rule: Option<&'static str>,
    /// What failed, for humans.
    pub detail: Option<String>,
    /// From here on, valid lists only, read from the signed bytes.
    pub sequence_number: Option<u64>,
    /// `ListIssueDateTime`.
    pub issued_at: Option<String>,
    /// `NextUpdate`.
    pub next_update: Option<String>,
    /// The TSL signer CA.
    pub anchor: Option<CertSummary>,
    /// The signer.
    pub signer: Option<CertSummary>,
    /// CA services in accord with a certificate.
    pub cas: Option<usize>,
    /// Warnings about a valid list: `no_ocsp_check`, `validity_warning_1`.
    pub warnings: Vec<Finding>,
    /// Services of a valid list that could not be processed and were left out.
    pub skipped: Vec<SkippedInfo>,
    /// The signer's OCSP status, when it was queried or supplied.
    pub signer_status: Option<SignerStatus>,
    /// `newer` or `same` against the previous list; null without it or for an invalid
    /// list.
    pub sequence: Option<&'static str>,
}

/// A service of the list left out.
#[derive(Serialize)]
pub struct SkippedInfo {
    /// Its provider.
    pub provider: String,
    /// Its name.
    pub name: String,
    /// Why it was left out.
    pub reason: String,
}

/// The signer's OCSP status.
#[derive(Serialize)]
pub struct SignerStatus {
    /// `good`; anything else makes the list invalid.
    pub status: &'static str,
    /// The responder asked, or `supplied` for a response given with the list.
    pub responder_url: String,
    /// The response's `producedAt`.
    pub produced_at: Option<String>,
}

/// Verifies `files` under the embedded TSL signer CA of `env`, or of the environment
/// whose CA issued the signer when `None`, at `at` or now, accepting a list up to
/// `grace` past its `NextUpdate` (TSLSIG-054). The signer's status is the one supplied
/// with the list, else asked for through what `online` opens, unless `offline` or `at`
/// is given: a status now says nothing about another time (TSLDET-023). `online` is
/// called only when it is needed.
///
/// # Errors
///
/// [`Error::TrustLoad`] for a previous list that does not parse; [`Error::Trust`] for a
/// preset its tier does not admit; what `online` returns. A list that fails verification
/// is no error but an invalid [`Verdict`].
pub fn verify<E: From<Error>>(
    files: &Files<'_>,
    env: Option<Env>,
    at: Option<Timestamp>,
    grace: Duration,
    offline: bool,
    online: impl FnOnce() -> Result<(Http, FileCache), E>,
) -> Result<Verdict, E> {
    let previous = files
        .previous
        .map(|(bytes, name)| {
            Tsl::parse(bytes)
                .map(|tsl| TslState::of(&tsl))
                .map_err(|e| Error::TrustLoad(format!("{name}: {e}")))
        })
        .transpose()?;
    let now = at.unwrap_or_else(Timestamp::now);
    let config = match env {
        Some(env) => Ok(TrustConfig::preset(env)),
        None => embedded_config_for(files.signature),
    }
    .map(|config| TrustConfig {
        // TSLSIG-054: how long past its NextUpdate the list stays usable.
        tsl_grace_period: grace,
        ..config
    });
    if let (Ok(config), Some(env)) = (&config, env) {
        config.validate(env.tier()).map_err(Error::Trust)?;
    }
    let mut sequence = None;
    let result = config.map_err(Failure::Tsl).and_then(|config| {
        // TSLDET-005: the detached signature over the bytes as read, before any parsing.
        let mut verified =
            Tsl::parse_verified(files.list, files.signature, &config, now).map_err(Failure::Tsl)?;
        if previous.is_some() {
            // TSLSIG-053: a list may not roll back behind the one given as previous.
            sequence = Some(
                verified
                    .check_sequence(previous.as_ref())
                    .map_err(Failure::Tsl)?,
            );
        }
        // TSLDET-020: a supplied status is verified like a queried one and replaces it.
        if let Some(status) = files.signer_status {
            verified
                .check_signer_status_supplied(status, now, &config.algorithms)
                .map_err(Failure::Tsl)?;
        }
        // The status now says nothing about another time (TSLDET-023).
        if files.signer_status.is_none() && !offline && at.is_none() {
            let (transport, store) = online().map_err(Failure::Host)?;
            let checker = OcspChecker::new(&config, &transport, Timestamp::now).with_store(store);
            block_on(verified.check_signer_status(&checker)).map_err(Failure::Tsl)?;
        }
        Ok(verified)
    });
    let result = match result {
        Err(Failure::Host(e)) => return Err(e),
        Err(Failure::Tsl(e)) => Err(e),
        Ok(verified) => Ok(verified),
    };
    let mut verdict = verdict(files.source.clone(), env, now, &result);
    verdict.sequence = sequence.map(|s| match s {
        Sequence::Same => "same",
        _ => "newer",
    });
    Ok(verdict)
}

/// What can stop a verification: a verdict on the list, or the host.
enum Failure<E> {
    Tsl(TslError),
    Host(E),
}

fn verdict(
    source: String,
    env: Option<Env>,
    now: Timestamp,
    result: &Result<VerifiedTsl, TslError>,
) -> Verdict {
    let mut verdict = Verdict {
        source,
        environment: env.map_or("auto", Env::as_str),
        at: now.to_string(),
        result: "invalid",
        tier: None,
        code: None,
        code_number: None,
        rule: None,
        detail: None,
        sequence_number: None,
        issued_at: None,
        next_update: None,
        anchor: None,
        signer: None,
        cas: None,
        warnings: Vec::new(),
        skipped: Vec::new(),
        signer_status: None,
        sequence: None,
    };
    match result {
        Ok(verified) => {
            verdict.result = "valid";
            verdict.tier = Some(match verified.tier {
                Tier::Prod => "prod",
                Tier::NonProd => "nonprod",
            });
            verdict.sequence_number = Some(verified.tsl.sequence_number);
            verdict.issued_at = Some(verified.tsl.issued_at.to_string());
            verdict.next_update = verified.tsl.next_update.map(|t| t.to_string());
            verdict.anchor = Some(CertSummary::new(&verified.anchor));
            verdict.signer = Some(CertSummary::new(&verified.signer));
            verdict.cas = Some(verified.tsl.intermediate_cas().len());
            verdict.warnings = verified.warnings.iter().map(Finding::from).collect();
            verdict.skipped = verified
                .tsl
                .skipped
                .iter()
                .map(|s| SkippedInfo {
                    provider: s.provider.clone(),
                    name: s.name.clone(),
                    reason: s.reason.clone(),
                })
                .collect();
            verdict.signer_status = verified.signer_status.as_ref().map(|r| SignerStatus {
                status: r.status.as_str(),
                responder_url: if r.responder_url.is_empty() {
                    "supplied".to_owned()
                } else {
                    r.responder_url.clone()
                },
                produced_at: r.produced_at.map(|t| t.to_string()),
            });
        }
        Err(e) => {
            verdict.code = Some(e.code.as_str());
            verdict.code_number = e.code.number();
            verdict.rule = Some(e.rule);
            verdict.detail = Some(e.detail.clone());
        }
    }
    verdict
}

/// The Tab_PKI_405 names of `types` (gemSpec_OID's certificate type table, `C.FD.TLS-S`),
/// an OID the table does not name as its dotted string.
fn type_names(types: Option<&[ObjectIdentifier]>) -> Vec<String> {
    types
        .unwrap_or_default()
        .iter()
        .map(|oid| {
            ti_pki::oid::lookup(oid)
                .map(|info| info.description)
                .filter(|name| name.starts_with("C."))
                .map_or_else(|| oid.to_string(), str::to_owned)
        })
        .collect()
}

/// Whether `text` contains any of `filters`, ignoring case; true without filters.
fn contains(filters: &[String], text: &str) -> bool {
    let text = text.to_lowercase();
    filters.is_empty() || filters.iter().any(|f| text.contains(&f.to_lowercase()))
}

/// Whether `root` issued `ca`: its subject is the CA's issuer. The CA is among the kept
/// ones, so a root of that name has verified its signature.
fn issued_by(ca: &Certificate, root: &Certificate) -> bool {
    root.subject() == ca.issuer()
}

fn describe(
    ca: &Intermediate,
    rejection: Option<&'static str>,
    now: Timestamp,
    store: &TrustStore,
) -> CaInfo {
    let cert = &ca.certificate;
    CaInfo {
        issuable_types: type_names(store.tsl_types_of(cert)),
        revoked_since: ca.revoked_since.map(|t| t.to_string()),
        common_name: cert.subject_cn().to_owned(),
        subject: cert.subject().to_string(),
        issuer: cert.issuer().to_string(),
        provider: ca.provider.clone(),
        not_before: cert.not_before().to_string(),
        not_after: cert.not_after().to_string(),
        not_after_at: cert.not_after(),
        validity: ti_pki::model::validity(cert, now),
        policies: cert.policies().iter().map(Oid::new).collect(),
        path_len: cert.basic_constraints().and_then(|b| b.path_len_constraint),
        rejection,
        sha256: cert.fingerprint_sha256(),
        pem: cert.to_pem(),
    }
}

/// `http` or `cache`: where the list's bytes came from.
pub fn source_name(meta: &Meta) -> &'static str {
    match meta.source {
        Source::Http => "http",
        _ => "cache",
    }
}
