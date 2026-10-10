//! `ti pki tsl show`: the TSL's CAs under the verified roots that signed them, and the
//! ones no verified root signed. The list is read from its signed bytes once its
//! signature, signer and `NextUpdate` verified (`spec/tsl-xmldsig`); a CA still counts
//! only if a verified root signed it, and what is shown about a CA comes from its
//! certificate.
//!
//! `ti pki tsl verify`: a TSL file's signature and signer under the embedded TSL signer
//! CA of an environment (`spec/tsl-xmldsig` parts A and B), offline.

use std::time::Duration;

use serde::Serialize;
use sha2::{Digest, Sha256};
use ti_pki::load::{Meta, Source, SystemClock};
use ti_pki::ocsp::OcspChecker;
use ti_pki::tsl::{self, Intermediate, Tsl};
use ti_pki::tsl_signature::{Sequence, TslError, TslState, VerifiedTsl, embedded_config_for};
use ti_pki::{Certificate, Clock, Tier, Timestamp, TrustConfig, TrustStore};
use ti_report::tsl::{CertSummary, Finding, rejection_code};

use crate::block::block_on;
use crate::cli::{
    CaFilterArgs, Environment, GlobalArgs, TrustArgs, TslBundleArgs, TslExportArgs, TslShowArgs,
    TslVerifyArgs,
};
use crate::error::{CliError, Exit};
use crate::output::document::{date, when};
use crate::output::{Document, Line, OidInfo, Output, SCHEMA, Tone, hex, pem};
use crate::trust::Session;

/// The JSON document.
#[derive(Serialize)]
struct Report {
    schema: u32,
    environment: &'static str,
    source: SourceInfo,
    insecure_transport: bool,
    /// The C.TSL.SIG certificate the list is signed with.
    signer: String,
    /// The TSL signer CA that issued it.
    tsl_signer_ca: String,
    /// `no_ocsp_check`, `validity_warning_1`.
    warnings: Vec<&'static str>,
    sequence_number: u64,
    issued_at: String,
    #[serde(skip)]
    issued_at_ts: Timestamp,
    next_update: Option<String>,
    #[serde(skip)]
    next_update_ts: Option<Timestamp>,
    /// Past `next_update`: a newer list should exist.
    overdue: bool,
    /// Over the whole list, whatever the filters.
    counts: Counts,
    /// The verified roots with the CAs they signed, after the filters.
    roots: Vec<RootEntry>,
    /// The CAs no verified root signed, after the filters.
    rejected: Vec<CaInfo>,
    /// Whether filters left anything out.
    filtered: bool,
}

#[derive(Serialize)]
struct SourceInfo {
    /// `http` or `cache`.
    source: &'static str,
    /// When the TSL was downloaded or last confirmed.
    fetched_at: String,
    #[serde(skip)]
    fetched_at_ts: Timestamp,
}

#[derive(Serialize)]
struct Counts {
    /// CA services in accord with a certificate: the candidates.
    listed: usize,
    /// Signed by a verified root; these take part in chain building.
    kept: usize,
    rejected: usize,
}

#[derive(Serialize)]
struct RootEntry {
    common_name: String,
    not_after: String,
    validity: &'static str,
    cas: Vec<CaInfo>,
}

#[derive(Serialize)]
struct CaInfo {
    common_name: String,
    subject: String,
    issuer: String,
    /// The TSPName the TSL lists the CA under.
    provider: String,
    not_before: String,
    not_after: String,
    #[serde(skip)]
    not_after_at: Timestamp,
    /// `valid`, `expired` or `not_yet_valid`, now.
    validity: &'static str,
    /// The certificate policies the CA certificate asserts.
    policies: Vec<OidInfo>,
    /// The certificate's path length constraint.
    path_len: Option<u8>,
    /// Why no verified root signed it: `not_ca`, `self_signed`, `unknown_issuer`,
    /// `bad_signature`; absent for kept CAs.
    rejection: Option<&'static str>,
    sha256: String,
    pem: String,
}

/// Runs `ti pki tsl show`.
pub fn show(args: &TslShowArgs, global: &GlobalArgs, out: &Output) -> Result<Exit, CliError> {
    let Loaded {
        env,
        session,
        material,
        meta,
        verified,
        matched,
        now,
        ..
    } = load(&args.trust, global, out)?;
    let list = &verified.tsl;
    let roots = material.store.roots();

    let wanted = |ca: &Intermediate| args.filter.wants(ca);
    let mut root_entries: Vec<RootEntry> = roots
        .iter()
        .filter(|root| !args.rejected && args.filter.wants_root(root))
        .map(|root| RootEntry {
            common_name: root.subject_cn().to_owned(),
            not_after: root.not_after().to_string(),
            validity: super::validity(root, now),
            cas: matched
                .intermediates
                .iter()
                .filter(|ca| issued_by(&ca.certificate, root) && wanted(ca))
                .map(|ca| describe(ca, None, now))
                .collect(),
        })
        .collect();
    let any_ca_filter = args.filter.ca.is_some() || args.filter.provider.is_some();
    if any_ca_filter {
        root_entries.retain(|root| !root.cas.is_empty());
    }
    let rejected: Vec<CaInfo> = matched
        .rejected
        .iter()
        .filter(|(ca, _)| args.filter.root.is_none() && wanted(ca))
        .map(|(ca, reason)| describe(ca, Some(rejection_code(*reason)), now))
        .collect();

    let report = Report {
        schema: SCHEMA,
        environment: env.as_str(),
        source: SourceInfo {
            source: source_name(&meta),
            fetched_at: meta.fetched_at.to_string(),
            fetched_at_ts: meta.fetched_at,
        },
        insecure_transport: session.insecure,
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
        filtered: args.rejected || any_ca_filter || args.filter.root.is_some(),
    };
    if out.is_json() {
        out.json(&report)?;
    } else {
        out.render(&document(&report, args.filter.ca.is_some()))?;
    }
    Ok(Exit::Ok)
}

/// The JSON document of `ti pki tsl verify`.
#[derive(Serialize)]
struct VerifyReport {
    schema: u32,
    /// The file name, or `<stdin>`.
    source: String,
    /// `--env`: `auto` or the environment asked for.
    environment: &'static str,
    /// The validation time.
    at: String,
    /// `valid` or `invalid`.
    result: &'static str,
    /// `prod` or `nonprod`, from the TSL signer CA; valid lists only.
    tier: Option<&'static str>,
    /// The result code of an invalid list, e.g. `xml_signature_error`.
    code: Option<&'static str>,
    /// Its gemSpec_PKI Tab_PKI_274 number, if it has one.
    code_number: Option<u16>,
    /// The rule of `spec/tsl-xmldsig` that failed, e.g. `TSLSIG-018`.
    rule: Option<&'static str>,
    detail: Option<String>,
    /// From here on, valid lists only, read from the signed bytes.
    sequence_number: Option<u64>,
    issued_at: Option<String>,
    next_update: Option<String>,
    signing_time: Option<String>,
    anchor: Option<CertSummary>,
    signer: Option<CertSummary>,
    /// CA services in accord with a certificate.
    cas: Option<usize>,
    /// Warnings about a valid list: `no_ocsp_check`, `validity_warning_1`.
    warnings: Vec<Finding>,
    /// Services of a valid list that could not be processed and were left out.
    skipped: Vec<SkippedInfo>,
    /// The signer's OCSP status, when it was queried.
    signer_status: Option<SignerStatus>,
    /// `newer` or `same` against `--previous`; null without it or for an invalid list.
    sequence: Option<&'static str>,
}

#[derive(Serialize)]
struct SkippedInfo {
    provider: String,
    name: String,
    reason: String,
}

#[derive(Serialize)]
struct SignerStatus {
    /// `good`; anything else makes the list invalid.
    status: &'static str,
    responder_url: String,
    produced_at: Option<String>,
}

/// Runs `ti pki tsl verify`.
pub fn verify(args: &TslVerifyArgs, global: &GlobalArgs, out: &Output) -> Result<Exit, CliError> {
    let source = crate::input::read(&args.file)?;
    let previous = args
        .previous
        .as_deref()
        .map(|path| {
            let previous = crate::input::read(path)?;
            Tsl::parse(&previous.bytes)
                .map(|tsl| TslState::of(&tsl))
                .map_err(|e| CliError::TrustLoad(format!("{}: {e}", previous.name)))
        })
        .transpose()?;
    let now = args.at.unwrap_or_else(|| SystemClock.now());
    let grace = Duration::from_hours(24 * u64::from(args.grace));
    let config = match args.env.concrete() {
        Some(env) => Ok(TrustConfig {
            tsl_grace_period: grace,
            ..TrustConfig::preset(env)
        }),
        None => embedded_config_for(&source.bytes).map(|config| TrustConfig {
            tsl_grace_period: grace,
            ..config
        }),
    };
    if let (Ok(config), Some(env)) = (&config, args.env.concrete()) {
        config.validate(env.tier()).map_err(CliError::Trust)?;
    }
    let mut sequence = None;
    let result = config.map_err(VerifyFailure::from).and_then(|config| {
        let mut verified = Tsl::parse_verified(&source.bytes, &config, now)?;
        if previous.is_some() {
            sequence = Some(verified.check_sequence(previous.as_ref())?);
        }
        // The status now says nothing about another time.
        if !args.offline && args.at.is_none() {
            let transport = crate::http::transport(&global.net, out.verbosity())?;
            let checker = OcspChecker::new(&config, &transport, SystemClock);
            block_on(verified.check_signer_status(&checker))?;
        }
        Ok(verified)
    });
    let result = match result {
        Err(VerifyFailure::Cli(e)) => return Err(e),
        Err(VerifyFailure::Tsl(e)) => Err(e),
        Ok(verified) => Ok(verified),
    };
    let mut report = verify_report(source.name, args.env, now, &result);
    report.sequence = sequence.map(|s| match s {
        Sequence::Same => "same",
        _ => "newer",
    });
    if out.is_json() {
        out.json(&report)?;
    } else {
        out.render(&verify_document(&report))?;
    }
    Ok(if result.is_ok() {
        Exit::Ok
    } else {
        Exit::Invalid
    })
}

/// What can stop `tsl verify`: a verdict on the list, or the tool itself.
enum VerifyFailure {
    Tsl(TslError),
    Cli(CliError),
}

impl From<TslError> for VerifyFailure {
    fn from(e: TslError) -> Self {
        VerifyFailure::Tsl(e)
    }
}

impl From<CliError> for VerifyFailure {
    fn from(e: CliError) -> Self {
        VerifyFailure::Cli(e)
    }
}

fn verify_report(
    source: String,
    env: Environment,
    now: Timestamp,
    result: &Result<VerifiedTsl, TslError>,
) -> VerifyReport {
    let mut report = VerifyReport {
        schema: SCHEMA,
        source,
        environment: env.concrete().map_or("auto", |e| e.as_str()),
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
        signing_time: None,
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
            report.result = "valid";
            report.tier = Some(match verified.tier {
                Tier::Prod => "prod",
                Tier::NonProd => "nonprod",
            });
            report.sequence_number = Some(verified.tsl.sequence_number);
            report.issued_at = Some(verified.tsl.issued_at.to_string());
            report.next_update = verified.tsl.next_update.map(|t| t.to_string());
            report.signing_time = Some(verified.signing_time.clone());
            report.anchor = Some(CertSummary::new(&verified.anchor));
            report.signer = Some(CertSummary::new(&verified.signer));
            report.cas = Some(verified.tsl.intermediate_cas().len());
            report.warnings = verified.warnings.iter().map(Finding::from).collect();
            report.skipped = verified
                .tsl
                .skipped
                .iter()
                .map(|s| SkippedInfo {
                    provider: s.provider.clone(),
                    name: s.name.clone(),
                    reason: s.reason.clone(),
                })
                .collect();
            report.signer_status = verified.signer_status.as_ref().map(|r| SignerStatus {
                status: r.status.as_str(),
                responder_url: r.responder_url.clone(),
                produced_at: r.produced_at.map(|t| t.to_string()),
            });
        }
        Err(e) => {
            report.code = Some(e.code.as_str());
            report.code_number = e.code.number();
            report.rule = Some(e.rule);
            report.detail = Some(e.detail.clone());
        }
    }
    report
}

fn verify_document(report: &VerifyReport) -> Document {
    let mut doc = Document::default();
    let at = Timestamp::parse_rfc3339(&report.at).map_or_else(|| report.at.clone(), date);
    let Some(sequence) = report.sequence_number else {
        let code = report.code.unwrap_or_default();
        let number = report
            .code_number
            .map_or_else(String::new, |n| format!(" ({n})"));
        doc.paragraph(
            Line::strong("TSL")
                .and_text(format!(" · {} · ", report.source))
                .and_status(Tone::Bad, "invalid"),
        );
        doc.field(
            "reason",
            Line::code(format!("{code}{number}"))
                .and_dim(format!(" {}", report.rule.unwrap_or_default())),
        );
        doc.field(
            "detail",
            Line::text(report.detail.clone().unwrap_or_default()),
        );
        doc.field("environment", Line::text(report.environment));
        doc.field("verified at", Line::text(at));
        return doc;
    };
    doc.paragraph(
        Line::strong(format!("TSL #{sequence}"))
            .and_text(format!(" · {} · ", report.tier.unwrap_or_default()))
            .and_status(Tone::Good, "valid"),
    );
    if let Some(anchor) = &report.anchor {
        doc.field("TSL signer CA", Line::text(&anchor.common_name));
    }
    if let Some(signer) = &report.signer {
        doc.field(
            "signer",
            Line::text(&signer.common_name).and_dim(format!(" · serial {}", signer.serial)),
        );
    }
    if let Some(signing_time) = &report.signing_time {
        doc.field("signed", Line::text(signing_time));
    }
    let next = report.next_update.as_deref().unwrap_or("closed list");
    doc.field(
        "issued",
        Line::text(report.issued_at.clone().unwrap_or_default())
            .and_dim(format!(" · next update {next}")),
    );
    doc.field(
        "CAs",
        Line::text(report.cas.unwrap_or_default().to_string()),
    );
    if let Some(status) = &report.signer_status {
        doc.field(
            "signer status",
            Line::status(Tone::Good, status.status).and_dim(format!(" · {}", status.responder_url)),
        );
    }
    if let Some(sequence) = report.sequence {
        doc.field("previous", Line::text(format!("this list is {sequence}")));
    }
    doc.field("verified at", Line::text(at));
    for warning in &report.warnings {
        doc.field(
            "warning",
            Line::status(Tone::Warn, super::tsl_warning_text(warning.code))
                .and_dim(format!(" {} · {}", warning.rule, warning.detail)),
        );
    }
    for skipped in &report.skipped {
        doc.field(
            "skipped",
            Line::text(format!("{} · {}", skipped.provider, skipped.name))
                .and_dim(format!(" · {}", skipped.reason)),
        );
    }
    doc
}

/// Whether `root` issued `ca`: its subject is the CA's issuer. The CA is among the kept
/// ones, so a root of that name has verified its signature.
/// Runs `ti pki tsl bundle`: the CAs `tsl show` keeps under the verified roots, with its
/// filters; the rejected ones never.
pub fn bundle(args: &TslBundleArgs, global: &GlobalArgs, out: &Output) -> Result<Exit, CliError> {
    super::bundle::refuse_existing(&args.bundle)?;
    let Loaded {
        env,
        session,
        material,
        verified,
        matched,
        ..
    } = load(&args.trust, global, out)?;
    let roots = material.store.roots();
    let certificates = matched
        .intermediates
        .iter()
        .filter(|ca| {
            args.filter.wants(ca)
                && roots
                    .iter()
                    .any(|root| issued_by(&ca.certificate, root) && args.filter.wants_root(root))
        })
        .map(|ca| ca.certificate.clone())
        .collect();
    super::bundle::write(
        super::bundle::Found {
            environment: env.as_str(),
            certificates,
            tsl_sequence_number: Some(verified.tsl.sequence_number),
            trust: material.info,
            insecure_transport: session.insecure,
        },
        &args.bundle,
        out,
    )
}

/// The JSON document of `ti pki tsl export`; `schema` is added on output.
#[derive(Serialize)]
struct ExportReport {
    environment: &'static str,
    /// The list's `Id`.
    id: String,
    sequence_number: u64,
    issued_at: String,
    next_update: Option<String>,
    /// Of the bytes as published.
    sha256: String,
    bytes: usize,
    url: String,
    /// `http`, `cache`, …: where the bytes came from.
    source: &'static str,
    fetched_at: String,
    /// The file written; absent when the TSL went to stdout.
    output: Option<String>,
}

/// Runs `ti pki tsl export`: the TSL's bytes as published, once they verified, to stdout
/// or `-o`; what was written as a report.
pub fn export(args: &TslExportArgs, global: &GlobalArgs, out: &Output) -> Result<Exit, CliError> {
    if let Some(path) = &args.output
        && !args.force
        && path.exists()
    {
        return Err(CliError::OutputExists(path.display().to_string()));
    }
    let Loaded {
        env,
        config,
        bytes,
        meta,
        verified,
        ..
    } = load(&args.trust, global, out)?;
    if let Some(path) = &args.output {
        super::write_file(path, &bytes, args.force, false)?;
    } else if !out.is_json() {
        use std::io::Write as _;
        let mut stdout = std::io::stdout().lock();
        stdout.write_all(&bytes)?;
        stdout.flush()?;
        return Ok(Exit::Ok);
    }
    let list = &verified.tsl;
    let report = ExportReport {
        environment: env.as_str(),
        id: list.id.clone(),
        sequence_number: list.sequence_number,
        issued_at: list.issued_at.to_string(),
        next_update: list.next_update.map(|t| t.to_string()),
        sha256: hex(&Sha256::digest(&bytes)),
        bytes: bytes.len(),
        url: config.tsl_url.to_string(),
        source: source_name(&meta),
        fetched_at: meta.fetched_at.to_string(),
        output: args.output.as_ref().map(|p| p.display().to_string()),
    };
    super::connector::emit(out, Exit::Ok, &report, |doc| {
        doc.paragraph(
            Line::strong(format!("TSL {}", report.sequence_number))
                .and_text(format!(" · {}", report.environment)),
        );
        doc.field("id", Line::code(&report.id));
        doc.field("issued", when(list.issued_at));
        if let Some(next) = list.next_update {
            doc.field("next update", when(next));
        }
        doc.field("sha-256", Line::code(&report.sha256));
        doc.field("bytes", report.bytes.to_string());
        if let Some(output) = &report.output {
            doc.field("to", Line::code(output));
        }
    })
}

/// The verified TSL of an environment and what its verified roots make of it.
struct Loaded {
    env: ti_pki::Env,
    config: TrustConfig,
    session: Session,
    material: crate::trust::Material,
    /// The TSL as published.
    bytes: Vec<u8>,
    meta: Meta,
    verified: VerifiedTsl,
    matched: tsl::Matched,
    now: Timestamp,
}

/// The roots first: they decide which of the TSL's CAs count, and loading them refreshes
/// the cached TSL too. The TSL is then read from its signed bytes once it verified.
fn load(trust: &TrustArgs, global: &GlobalArgs, out: &Output) -> Result<Loaded, CliError> {
    let env = super::concrete(trust.env, global)?;
    let config = TrustConfig::preset(env);
    config.validate(env.tier()).map_err(CliError::Trust)?;
    let session = Session::new(global, trust.offline, out)?;
    let material = session.load(&config, env.tier(), trust.at)?;
    let now = trust.at.unwrap_or_else(|| SystemClock.now());
    let (bytes, meta) = session.tsl(&config)?;
    let verified = Tsl::parse_verified(&bytes, &config, now)
        .map_err(|e| CliError::TrustLoad(format!("TSL: {e}")))?;
    let matched = tsl::match_to_roots(
        verified.tsl.intermediate_cas(),
        &TrustStore::new(material.store.roots().iter().cloned()),
        &config.algorithms,
    );
    Ok(Loaded {
        env,
        config,
        session,
        material,
        bytes,
        meta,
        verified,
        matched,
        now,
    })
}

impl CaFilterArgs {
    /// Whether `ca` passes `--ca` and `--provider`.
    fn wants(&self, ca: &Intermediate) -> bool {
        contains(self.ca.as_deref(), ca.certificate.subject_cn())
            && contains(self.provider.as_deref(), &ca.provider)
    }

    /// Whether `root` passes `--root`.
    fn wants_root(&self, root: &Certificate) -> bool {
        contains(self.root.as_deref(), root.subject_cn())
    }
}

fn contains(filter: Option<&str>, text: &str) -> bool {
    filter.is_none_or(|f| text.to_lowercase().contains(&f.to_lowercase()))
}

fn issued_by(ca: &Certificate, root: &Certificate) -> bool {
    root.subject() == ca.issuer()
}

fn describe(ca: &Intermediate, rejection: Option<&'static str>, now: Timestamp) -> CaInfo {
    let cert = &ca.certificate;
    CaInfo {
        common_name: cert.subject_cn().to_owned(),
        subject: cert.subject().to_string(),
        issuer: cert.issuer().to_string(),
        provider: ca.provider.clone(),
        not_before: cert.not_before().to_string(),
        not_after: cert.not_after().to_string(),
        not_after_at: cert.not_after(),
        validity: super::validity(cert, now),
        policies: cert.policies().iter().map(OidInfo::new).collect(),
        path_len: cert.basic_constraints().and_then(|b| b.path_len_constraint),
        rejection,
        sha256: hex(&Sha256::digest(cert.der())),
        pem: pem(cert.der()),
    }
}

fn source_name(meta: &Meta) -> &'static str {
    match meta.source {
        Source::Http => "http",
        _ => "cache",
    }
}

fn document(report: &Report, with_pem: bool) -> Document {
    let mut doc = Document::default();
    let mut head = Line::strong(format!("TSL #{}", report.sequence_number))
        .and_text(format!(" · {}", report.environment))
        .and_dim(format!(" · issued {}", date(report.issued_at_ts)));
    head = match report.next_update_ts {
        Some(next) if report.overdue => head
            .and_dim(format!(" · next update {}", date(next)))
            .and_text(" ")
            .and_status(Tone::Warn, "overdue"),
        Some(next) => head.and_dim(format!(" · next update {}", date(next))),
        None => head.and_dim(" · closed list"),
    };
    doc.paragraph(head.and_dim(format!(
        " · {} {}",
        report.source.source,
        when(report.source.fetched_at_ts)
    )));
    let mut signed = Line::text(format!(
        "signed by {} under {}",
        report.signer, report.tsl_signer_ca
    ));
    for warning in &report.warnings {
        signed = signed
            .and_text(" ")
            .and_status(Tone::Warn, super::tsl_warning_text(warning));
    }
    doc.paragraph(signed);
    let counts = &report.counts;
    let mut summary = Line::text(format!(
        "{} CAs: {} under a verified root, ",
        counts.listed, counts.kept
    ));
    summary = if counts.rejected == 0 {
        summary.and_text("none without")
    } else {
        summary.and_status(Tone::Bad, format!("{} without", counts.rejected))
    };
    if report.filtered {
        summary = summary.and_dim(" · filtered");
    }
    doc.paragraph(summary);

    let kept = report.roots.iter().flat_map(|root| {
        root.cas
            .iter()
            .map(move |ca| (ca, Line::text(&root.common_name)))
    });
    let rejected = report
        .rejected
        .iter()
        .map(|ca| (ca, Line::status(Tone::Bad, rejection_text(ca))));
    // Only what the CA certificates say: the TSL's per-CA metadata decides nothing.
    let rows = kept.chain(rejected).map(|(ca, root)| {
        let organization = super::organization(&ca.subject).unwrap_or_else(|| "-".to_owned());
        vec![
            Line::strong(&ca.common_name),
            Line::text(organization),
            root,
            super::validity_cell(ca.not_after_at, ca.validity),
        ]
    });
    doc.table(&["CA", "ORGANIZATION", "ROOT", "VALIDITY"], rows.collect());

    if with_pem {
        let cas = report
            .roots
            .iter()
            .flat_map(|root| &root.cas)
            .chain(&report.rejected);
        for ca in cas {
            doc.paragraph(Line::strong(&ca.common_name));
            doc.pem(&ca.pem);
        }
    }
    doc
}

/// Why no verified root signed `ca`, for the ROOT column.
fn rejection_text(ca: &CaInfo) -> String {
    let (issuer, _) = super::inspect::split_name(&ca.issuer);
    let issuer = issuer.unwrap_or_else(|| ca.issuer.clone());
    match ca.rejection.unwrap_or_default() {
        "self_signed" => "none: self-signed".to_owned(),
        "unknown_issuer" => format!("none: {issuer} is no verified root"),
        "bad_signature" => format!("none: signature of {issuer} fails"),
        "not_ca" => "none: not a CA certificate".to_owned(),
        other => format!("none: {other}"),
    }
}
