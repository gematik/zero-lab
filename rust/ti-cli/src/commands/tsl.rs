//! `ti pki tsl show`: the TSL's CAs under the verified roots that signed them, and the
//! ones no verified root signed. The TSL is not authenticated: of each entry only the
//! certificate and the provider name are used, and everything shown about a CA comes
//! from its signed certificate, never from the TSL's own metadata.
//!
//! `ti pki tsl verify`: a TSL file's signature and signer under the embedded TSL signer
//! CA of an environment (`spec/tsl-xmldsig` parts A and B), offline.

use serde::Serialize;
use sha2::{Digest, Sha256};
use ti_pki::load::{Meta, Source, SystemClock};
use ti_pki::tsl::{self, Intermediate, Rejection, Tsl};
use ti_pki::tsl_signature::{TslError, VerifiedTsl};
use ti_pki::{Certificate, Clock, Tier, Timestamp, TrustConfig, TrustStore};

use crate::cli::{Environment, GlobalArgs, TslShowArgs, TslVerifyArgs};
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
    let env = super::concrete(args.trust.env)?;
    let config = TrustConfig::preset(env);
    config.validate(env.tier()).map_err(CliError::Trust)?;
    let session = Session::new(global, args.trust.offline, out)?;
    // The roots first: they decide which of the TSL's CAs count, and loading them
    // refreshes the cached TSL too.
    let material = session.load(&config, env.tier())?;
    let (bytes, meta) = session.tsl(&config)?;
    let list = Tsl::parse(&bytes).map_err(|e| CliError::TrustLoad(format!("TSL: {e}")))?;
    let roots = material.store.roots();
    let matched = tsl::match_to_roots(
        list.intermediate_cas(),
        &TrustStore::new(roots.iter().cloned()),
        &config.algorithms,
    );
    let now = SystemClock.now();

    let contains = |filter: &Option<String>, text: &str| {
        filter
            .as_deref()
            .is_none_or(|f| text.to_lowercase().contains(&f.to_lowercase()))
    };
    let wanted = |ca: &Intermediate| {
        contains(&args.ca, ca.certificate.subject_cn()) && contains(&args.provider, &ca.provider)
    };
    let mut root_entries: Vec<RootEntry> = roots
        .iter()
        .filter(|root| !args.rejected && contains(&args.root, root.subject_cn()))
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
    let any_ca_filter = args.ca.is_some() || args.provider.is_some();
    if any_ca_filter {
        root_entries.retain(|root| !root.cas.is_empty());
    }
    let rejected: Vec<CaInfo> = matched
        .rejected
        .iter()
        .filter(|(ca, _)| args.root.is_none() && wanted(ca))
        .map(|(ca, reason)| describe(ca, Some(rejection(*reason)), now))
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
        filtered: args.rejected || any_ca_filter || args.root.is_some(),
    };
    if out.is_json() {
        out.json(&report)?;
    } else {
        out.render(&document(&report, args.ca.is_some()))?;
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
}

#[derive(Serialize)]
struct CertSummary {
    common_name: String,
    subject: String,
    /// Hexadecimal.
    serial: String,
    not_before: String,
    not_after: String,
    sha256: String,
}

impl CertSummary {
    fn new(cert: &Certificate) -> Self {
        CertSummary {
            common_name: cert.subject_cn().to_owned(),
            subject: cert.subject().to_string(),
            serial: hex(cert.serial()),
            not_before: cert.not_before().to_string(),
            not_after: cert.not_after().to_string(),
            sha256: hex(&Sha256::digest(cert.der())),
        }
    }
}

/// Runs `ti pki tsl verify`.
pub fn verify(args: &TslVerifyArgs, out: &Output) -> Result<Exit, CliError> {
    let source = crate::input::read(&args.file)?;
    let now = args.at.unwrap_or_else(|| SystemClock.now());
    let result = match args.env.concrete() {
        None => Tsl::parse_verified_auto(&source.bytes, now),
        Some(env) => {
            let config = TrustConfig::preset(env);
            config.validate(env.tier()).map_err(CliError::Trust)?;
            Tsl::parse_verified(&source.bytes, &config, now)
        }
    };
    let report = verify_report(source.name, args.env, now, &result);
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
    doc.field("verified at", Line::text(at));
    doc
}

/// Whether `root` issued `ca`: its subject is the CA's issuer. The CA is among the kept
/// ones, so a root of that name has verified its signature.
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

fn rejection(reason: Rejection) -> &'static str {
    match reason {
        Rejection::NotCa => "not_ca",
        Rejection::SelfSigned => "self_signed",
        Rejection::UnknownIssuer => "unknown_issuer",
        Rejection::BadSignature => "bad_signature",
        _ => "other",
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
    // Only what the CA certificates say: the TSL's own metadata is not authenticated.
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
    let issuer = issuer.unwrap_or(&ca.issuer);
    match ca.rejection.unwrap_or_default() {
        "self_signed" => "none: self-signed".to_owned(),
        "unknown_issuer" => format!("none: {issuer} is no verified root"),
        "bad_signature" => format!("none: signature of {issuer} fails"),
        "not_ca" => "none: not a CA certificate".to_owned(),
        other => format!("none: {other}"),
    }
}
