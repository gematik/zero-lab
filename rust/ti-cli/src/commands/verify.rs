//! `ti pki verify`: builds the chain to the TI roots through the TSL's CAs and
//! validates it the way a relying party would, OCSP included. `--offline` uses cached
//! or embedded trust material and skips revocation, and the report says so rather than
//! passing silently.

use std::sync::Arc;

use serde::Serialize;
use ti_pki::load::SystemClock;
use ti_pki::ocsp::OcspChecker;
use ti_pki::profile::{self, SelectReason};
use ti_pki::revocation::{
    ResponderAuthorization, RevocationMode, RevocationResult, RevocationStatus, Unchecked,
};
use ti_pki::trustdomain::detect_trust_domain;
use ti_pki::{
    Certificate, ChainPosition, Clock, Env, ErrorCode, Tier, Timestamp, TrustConfig, TrustStore,
    ValidationResult, Validator, detect_certificate_type,
};

use crate::block::block_on;
use crate::cli::{Environment, GlobalArgs, VerifyArgs};
use crate::error::{CliError, Exit};
use crate::input;
use crate::output::document::{TreeRow, when};
use crate::output::{Document, Line, Output, SCHEMA, Tone, pem};
use crate::trust::{Session, TrustInfo};

/// The JSON document.
#[derive(Serialize)]
struct Report {
    schema: u32,
    source: String,
    valid: bool,
    environment: EnvironmentInfo,
    at: String,
    #[serde(skip)]
    at_ts: Timestamp,
    certificate_type: Option<String>,
    profile: ProfileInfo,
    trust: TrustInfo,
    /// False offline or with revocation disabled; the verdict then says nothing about
    /// revocation.
    revocation_checked: bool,
    /// `hard-fail`, `soft-fail` or `disabled`.
    revocation_mode: &'static str,
    /// TLS certificates of downloads were not checked (`-k`).
    insecure_transport: bool,
    chain: Vec<ChainEntry>,
    errors: Vec<Finding>,
    warnings: Vec<Finding>,
    /// The end entity as `pki inspect` describes it, at the instant validated at.
    #[serde(skip)]
    details: super::inspect::CertificateInfo,
    /// The chain as a tree, with each certificate's verdict.
    #[serde(skip)]
    tree: Vec<TreeRow>,
}

#[derive(Serialize)]
struct EnvironmentInfo {
    name: &'static str,
    production: bool,
    /// How `--env auto` decided; absent when the environment was given.
    detection: Option<Detection>,
}

#[derive(Serialize)]
pub(super) struct Detection {
    method: &'static str,
    detail: String,
}

#[derive(Serialize)]
struct ProfileInfo {
    /// The profile validated against; `None` checks the chain only.
    name: Option<&'static str>,
    /// `cert`, `default`, `forced`, `ambiguous`, `none` or `disabled`.
    reason: &'static str,
    detail: String,
}

#[derive(Serialize)]
struct ChainEntry {
    position: &'static str,
    subject: String,
    common_name: String,
    not_after: String,
    /// What OCSP said; absent when not asked (offline, the root, or not reached).
    revocation: Option<RevocationEntry>,
    pem: String,
}

#[derive(Serialize)]
struct RevocationEntry {
    /// `good`, `revoked` or `unknown`.
    status: &'static str,
    /// Revocation reason, or why the status is unknown.
    reason: String,
    responder_url: String,
    /// Common name of the response's signer.
    responder: String,
    /// `issuer`, `delegate` or `same_tsp_delegate`; absent without a verified response.
    authorization: Option<&'static str>,
    produced_at: Option<String>,
    revoked_at: Option<String>,
}

#[derive(Serialize)]
struct Finding {
    code: String,
    /// Common name of the certificate concerned; empty when not tied to one.
    subject: String,
    message: String,
}

/// What one run established, for the report.
struct Run {
    source: String,
    env: Env,
    detection: Option<Detection>,
    at: Timestamp,
    profile: ProfileInfo,
    trust: TrustInfo,
    revocation: RevocationMode,
    offline: bool,
    insecure: bool,
    warnings: Vec<Finding>,
}

/// Runs the command; exit 0 when valid, 1 when not.
pub fn run(args: &VerifyArgs, global: &GlobalArgs, out: &Output) -> Result<Exit, CliError> {
    let source = input::read(&args.file)?;
    let certificates = |source: &input::Source| -> Result<Vec<Certificate>, CliError> {
        Ok(input::certificates(source, &args.p12_password)?
            .into_iter()
            .map(|loaded| loaded.certificate)
            .collect())
    };
    let mut certs = certificates(&source)?;
    for path in args.issuer.iter().chain(&args.intermediates) {
        certs.extend(certificates(&input::read(path)?)?);
    }
    let at = args.at.unwrap_or_else(|| SystemClock.now());

    let (env, detection) = environment(args.env, &certs, at)?;
    let config = TrustConfig::preset(env);
    config.validate(env.tier()).map_err(CliError::Trust)?;
    let session = Session::new(global, args.offline, out)?;
    let material = session.load(&config, env.tier())?;
    out.verbose(
        1,
        format_args!(
            "{env}: {} roots, {} TSL CAs from {}",
            material.info.roots, material.info.intermediates, material.info.source
        ),
    );

    let mut warnings = Vec::new();
    let (mut validator, profile) = validator(
        &args.profile,
        &config,
        material.store,
        &certs[0],
        &mut warnings,
    );
    validator.expected_fqdn.clone_from(&args.fqdn);
    let validated = block_on(async {
        if let Some(transport) = session.transport() {
            let checker = OcspChecker::new(&config, transport, SystemClock);
            validator.validate(&certs, at, &checker).await
        } else {
            // No OCSP offline. Set here, after the profile: config.validate rejects
            // Disabled under Prod, so this is the one place the relaxation happens, and
            // the report states it.
            validator.revocation = RevocationMode::Disabled;
            validator.validate(&certs, at, &Unchecked).await
        }
    });
    let result = validated.map_err(|source| CliError::Certificate {
        source_name: source_name(&args.file),
        source,
    })?;

    let run = Run {
        source: source.name,
        env,
        detection,
        at,
        profile,
        trust: material.info,
        revocation: validator.revocation,
        offline: args.offline,
        insecure: session.insecure,
        warnings,
    };
    let details = super::inspect::describe(
        &input::Loaded {
            certificate: certs[0].clone(),
            private_key: false,
            bag: None,
        },
        at,
    );
    let report = report(run, &certs[0], details, &result);
    if out.is_json() {
        out.json(&report)?;
    } else {
        out.render_views(&sections(&report), &summary(&report))?;
    }
    Ok(if report.valid {
        Exit::Ok
    } else {
        Exit::Invalid
    })
}

fn source_name(path: &std::path::Path) -> String {
    if path == std::path::Path::new("-") {
        "<stdin>".to_owned()
    } else {
        path.display().to_string()
    }
}

/// The environment to validate in; `auto` asks the certificates. Non-production
/// evidence maps to ref: ref and test share their roots, so the choice only matters
/// once the TSL and OCSP come into play.
pub(super) fn environment(
    choice: Environment,
    certs: &[Certificate],
    at: Timestamp,
) -> Result<(Env, Option<Detection>), CliError> {
    if let Some(env) = choice.concrete() {
        return Ok((env, None));
    }
    let found = detect_trust_domain(certs, at);
    let (Some(tier), Some(method)) = (found.domain, found.method) else {
        let tried: Vec<String> = found
            .steps
            .iter()
            .map(|step| format!("{}: {}", step.method, step.outcome))
            .collect();
        return Err(CliError::EnvironmentUndetected(tried.join("; ")));
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
    selector: &str,
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
    if selector == profile::NONE {
        return (
            Validator::new(config, store),
            chain_only("disabled", "chain only, as requested".into()),
        );
    }
    let cert_type = detect_certificate_type(ee);
    if selector == profile::AUTO {
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
                message: format!(
                    "{}; checked the chain only, pass --profile",
                    selection.detail
                ),
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
    // The value parser admits only auto, none and the profile names.
    let Some(p) = profile::lookup(selector) else {
        unreachable!("clap restricts --profile to known names");
    };
    let forced = |detail: String| ProfileInfo {
        name: Some(p.name),
        reason: "forced",
        detail,
    };
    let Some(t) = cert_type else {
        let validator = Validator {
            required_role_oids: p.required_role_oids.to_vec(),
            revocation: p.revocation_mode(config),
            ..Validator::new(config, store)
        };
        return (
            validator,
            forced("type not detected; checked the profile's roles only".into()),
        );
    };
    if !p.accepts(t) {
        warnings.push(Finding {
            code: "profile_type_mismatch".into(),
            subject: ee.subject_cn().to_owned(),
            message: format!("profile {p} does not accept type {t}"),
        });
    }
    (p.validator(config, store, t), forced(String::new()))
}

fn report(
    run: Run,
    ee: &Certificate,
    details: super::inspect::CertificateInfo,
    result: &ValidationResult,
) -> Report {
    let mut warnings = run.warnings;
    warnings.extend(result.warnings.iter().map(|w| Finding {
        code: w.code.to_string(),
        subject: w.subject.clone(),
        message: w.message.clone(),
    }));
    let checked = !run.offline && run.revocation != RevocationMode::Disabled;
    let complete = result.positions.last() == Some(&ChainPosition::Root);
    let failed = |i: usize| {
        let cn = result.chain[i].subject_cn();
        result.errors.iter().any(|e| e.subject == cn)
    };
    let tree = super::chain_tree(
        &result.chain,
        complete,
        run.at,
        |i| {
            if failed(i) {
                Line::status(Tone::Bad, "✗ ")
            } else {
                Line::status(Tone::Good, "✓ ")
            }
        },
        |i| {
            result
                .cert_results
                .get(i)
                .and_then(|r| r.revocation.as_ref())
                .map(|r| Line::text(" · ").and_line(ocsp_line(&revocation_entry(r))))
                .unwrap_or_default()
        },
    );
    Report {
        schema: SCHEMA,
        source: run.source,
        valid: result.valid,
        environment: EnvironmentInfo {
            name: run.env.as_str(),
            production: run.env.is_prod(),
            detection: run.detection,
        },
        at: run.at.to_string(),
        at_ts: run.at,
        certificate_type: detect_certificate_type(ee).map(|t| t.to_string()),
        profile: run.profile,
        trust: run.trust,
        revocation_checked: checked,
        revocation_mode: mode_name(run.revocation),
        insecure_transport: run.insecure,
        chain: result
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
                pem: pem(cert.der()),
            })
            .collect(),
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
        tree,
    }
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
            ResponderAuthorization::SameTspDelegate { .. } => "same_tsp_delegate",
            _ => "other",
        }),
        produced_at: r.produced_at.map(|t| t.to_string()),
        revoked_at: r.revoked_at.map(|t| t.to_string()),
    }
}

fn mode_name(mode: RevocationMode) -> &'static str {
    match mode {
        RevocationMode::HardFail => "hard-fail",
        RevocationMode::SoftFail => "soft-fail",
        RevocationMode::Disabled => "disabled",
    }
}

/// The terminal view: the end entity as `pki inspect` shows it, then the result, the
/// chain as a tree and the findings.
fn sections(report: &Report) -> Document {
    let mut doc = Document::default();
    super::inspect::certificate_sections(&mut doc, &report.details, report.at_ts);
    doc.section("Result");
    doc.field("result", verdict(report));
    doc.field("revocation", revocation_line(report));
    let env = &report.environment;
    let mut env_line = Line::code(env.name);
    if let Some(d) = &env.detection {
        env_line = env_line.and_dim(format!(" (detected: {})", d.detail));
    }
    doc.field("environment", env_line);
    doc.field("at", when(report.at_ts));
    doc.field("profile", profile_line(&report.profile));
    doc.field("trust", super::trust_line(&report.trust));
    if report.insecure_transport {
        doc.field(
            "transport",
            Line::status(Tone::Warn, "TLS not verified").and_dim(" (-k)"),
        );
    }

    doc.section("Trust");
    if report.tree.is_empty() {
        doc.paragraph(Line::dim("no chain to a trusted root"));
    }
    doc.tree(report.tree.clone());

    if !report.errors.is_empty() {
        doc.section("Errors");
        doc.items("", report.errors.iter().map(|f| finding(Tone::Bad, f)));
        if needs_issuer(report) {
            doc.paragraph(issuer_hint());
        }
    }
    if !report.warnings.is_empty() {
        doc.section("Warnings");
        doc.items("", report.warnings.iter().map(|f| finding(Tone::Warn, f)));
    }
    doc
}

/// `VALID`, or `INVALID` with the number of errors; and the number of warnings.
fn verdict(report: &Report) -> Line {
    let mut line = if report.valid {
        Line::status(Tone::Good, "VALID")
    } else {
        Line::status(Tone::Bad, "INVALID")
            .and_dim(format!(", {}", count(report.errors.len(), "error")))
    };
    if !report.warnings.is_empty() {
        line = line.and_dim(format!(", {}", count(report.warnings.len(), "warning")));
    }
    line
}

/// Only a missing issuer of the end entity is fixed by --issuer; a CA without its root
/// means the roots walk did not reach one at that time.
fn needs_issuer(report: &Report) -> bool {
    report.chain.len() == 1
        && report
            .errors
            .iter()
            .any(|e| e.code == ErrorCode::ChainIncomplete.as_str())
}

fn issuer_hint() -> Line {
    Line::dim("hint: ")
        .and_text("the issuing CA is not among the trusted CAs; pass it with ")
        .and_code("--issuer")
}

/// The Markdown view: the verdict and context as lines, the chain as a list, the
/// findings, the chain as PEM.
fn summary(report: &Report) -> Document {
    let mut doc = Document::default();
    let mut verdict = verdict(report);
    if let Some(ee) = report.chain.first() {
        verdict = verdict.and_text(" · ").and_strong(&ee.common_name);
    }
    if let Some(t) = &report.certificate_type {
        verdict = verdict.and_text(" · ").and_code(t);
    }
    doc.paragraph(verdict);

    let env = &report.environment;
    let mut context = Line::text(env.name);
    if env.detection.is_some() {
        context = context.and_dim(" (detected)");
    }
    context = context
        .and_dim(format!(" · at {}", when(report.at_ts)))
        .and_dim(" · profile ")
        .and_line(profile_line(&report.profile));
    doc.paragraph(context);
    doc.paragraph(Line::dim("revocation ").and_line(revocation_line(report)));
    doc.paragraph(Line::dim("trust ").and_line(super::trust_line(&report.trust)));
    if report.insecure_transport {
        doc.paragraph(Line::status(Tone::Warn, "TLS of downloads not verified").and_dim(" (-k)"));
    }

    if report.tree.is_empty() {
        doc.items("", [Line::dim("no chain to a trusted root")]);
    }
    doc.tree(report.tree.clone());

    if !report.errors.is_empty() || !report.warnings.is_empty() {
        let findings = report
            .errors
            .iter()
            .map(|f| finding(Tone::Bad, f))
            .chain(report.warnings.iter().map(|f| finding(Tone::Warn, f)));
        doc.section("Findings").items("", findings);
    }
    if needs_issuer(report) {
        doc.paragraph(issuer_hint());
    }
    let chain: String = report
        .chain
        .iter()
        .map(|entry| entry.pem.as_str())
        .collect();
    if !chain.is_empty() {
        doc.pem(chain);
    }
    doc
}

/// The outcome over the chain: the worst OCSP answer, not the mode. The mode is
/// named only when it is soft-fail, where a missing answer does not invalidate.
fn revocation_line(report: &Report) -> Line {
    if !report.revocation_checked {
        return Line::status(Tone::Warn, "not checked").and_dim(" (offline)");
    }
    let answers: Vec<&RevocationEntry> = report
        .chain
        .iter()
        .filter_map(|entry| entry.revocation.as_ref())
        .collect();
    let has = |status: RevocationStatus| answers.iter().any(|r| r.status == status.as_str());
    let line = if answers.is_empty() {
        Line::status(Tone::Warn, "not checked").and_dim(" (no chain to check)")
    } else if has(RevocationStatus::Revoked) {
        Line::status(Tone::Bad, "revoked")
    } else if has(RevocationStatus::Unknown) {
        Line::status(Tone::Warn, "unknown").and_dim(" (no usable OCSP answer, see chain)")
    } else {
        // The root has no issuer to ask; every other certificate needs an answer.
        let needed = report
            .chain
            .iter()
            .filter(|entry| entry.position != ChainPosition::Root.as_str())
            .count();
        let n = answers.len();
        if n < needed {
            Line::status(Tone::Warn, "incomplete")
                .and_dim(format!(" (OCSP answered for {n} of {needed} certificates)"))
        } else {
            Line::status(Tone::Good, "not revoked").and_dim(format!(
                " (OCSP for {n} certificate{})",
                if n == 1 { "" } else { "s" }
            ))
        }
    };
    if report.revocation_mode == mode_name(RevocationMode::SoftFail) {
        line.and_dim(" · soft-fail: a missing answer does not invalidate")
    } else {
        line
    }
}

fn ocsp_line(r: &RevocationEntry) -> Line {
    let tone = match r.status {
        s if s == RevocationStatus::Good.as_str() => Tone::Good,
        s if s == RevocationStatus::Revoked.as_str() => Tone::Bad,
        _ => Tone::Warn,
    };
    let mut line = Line::status(tone, format!("OCSP {}", r.status));
    if !r.responder.is_empty() {
        let how = r
            .authorization
            .map_or(String::new(), |a| format!(", {}", a.replace('_', " ")));
        line = line.and_dim(format!(" by {}{how}", r.responder));
    }
    if !r.reason.is_empty() {
        line = line.and_dim(format!(": {}", r.reason));
    }
    line
}

fn profile_line(profile: &ProfileInfo) -> Line {
    let why = match (profile.reason, profile.detail.as_str()) {
        (reason, "") => reason.to_owned(),
        ("forced", detail) => format!("forced; {detail}"),
        (_, detail) => detail.to_owned(),
    };
    match profile.name {
        Some(name) => Line::code(name).and_dim(format!(" ({why})")),
        None => Line::dim(format!("none ({why})")),
    }
}

/// `error <code> · <subject>: <message>`: the leading word keeps errors and warnings
/// apart without color, in Markdown and when copied.
fn finding(tone: Tone, f: &Finding) -> Line {
    let kind = if tone == Tone::Bad {
        "error"
    } else {
        "warning"
    };
    let line = Line::status(tone, kind).and_text(" ").and_code(&f.code);
    let line = if f.subject.is_empty() {
        line
    } else {
        line.and_dim(format!(" · {}", f.subject))
    };
    line.and_text(format!(": {}", f.message))
}

/// `2 errors`, `1 warning`.
fn count(n: usize, what: &str) -> String {
    format!("{n} {what}{}", if n == 1 { "" } else { "s" })
}
