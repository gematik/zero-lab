//! `tir pki verify`: builds the chain to the embedded TI roots and validates it the way
//! a relying party would, except for revocation. Stage 2 is offline: no TSL, no OCSP,
//! and the report says so rather than passing silently.

use core::pin::pin;
use core::task::{Context, Poll, Waker};
use std::sync::Arc;

use serde::Serialize;
use ti_pki::load::SystemClock;
use ti_pki::profile::{self, SelectReason};
use ti_pki::revocation::{RevocationMode, Unchecked};
use ti_pki::trustdomain::detect_trust_domain;
use ti_pki::{
    Certificate, ChainPosition, Clock, Env, ErrorCode, Tier, Timestamp, TrustConfig, TrustStore,
    ValidationResult, Validator, detect_certificate_type, roots,
};

use crate::cli::{Environment, VerifyArgs};
use crate::error::{CliError, Exit};
use crate::input;
use crate::output::document::when;
use crate::output::{Document, Line, Output, SCHEMA, Tone};

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
    /// Always false offline; the verdict then says nothing about revocation.
    revocation_checked: bool,
    chain: Vec<ChainEntry>,
    errors: Vec<Finding>,
    warnings: Vec<Finding>,
}

#[derive(Serialize)]
struct EnvironmentInfo {
    name: &'static str,
    production: bool,
    /// How `--env auto` decided; absent when the environment was given.
    detection: Option<Detection>,
}

#[derive(Serialize)]
struct Detection {
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
}

#[derive(Serialize)]
struct Finding {
    code: String,
    /// Common name of the certificate concerned; empty when not tied to one.
    subject: String,
    message: String,
}

/// Runs the command; exit 0 when valid, 1 when not.
pub fn run(args: &VerifyArgs, out: &Output) -> Result<Exit, CliError> {
    let source = input::read(&args.file)?;
    let mut certs = input::certificates(&source)?;
    for path in args.issuer.iter().chain(&args.intermediates) {
        certs.extend(input::certificates(&input::read(path)?)?);
    }
    let at = args.at.unwrap_or_else(|| SystemClock.now());

    let (env, detection) = environment(args.env, &certs, at)?;
    let config = TrustConfig::preset(env);
    config.validate(env.tier()).map_err(CliError::Trust)?;
    let store = roots::load(&config, at).map_err(CliError::Trust)?.store();
    out.verbose(
        1,
        format_args!("{} roots of {env} trusted at {at}", store.len()),
    );

    let mut warnings = Vec::new();
    let (mut validator, profile) = validator(
        &args.profile,
        &config,
        Arc::new(store),
        &certs[0],
        &mut warnings,
    );
    // No OCSP offline. Set explicitly: config.validate rejects Disabled under Prod, so
    // this is the only place the relaxation happens, and the report states it.
    validator.revocation = RevocationMode::Disabled;
    let result = offline(validator.validate(&certs, at, &Unchecked)).map_err(|source| {
        CliError::Certificate {
            source_name: source_name(&args.file),
            source,
        }
    })?;

    let report = report(
        source.name,
        env,
        detection,
        at,
        &certs[0],
        profile,
        &result,
        warnings,
    );
    if out.is_json() {
        out.json(&report)?;
    } else {
        out.render(&document(&report))?;
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
fn environment(
    choice: Environment,
    certs: &[Certificate],
    at: Timestamp,
) -> Result<(Env, Option<Detection>), CliError> {
    let env = match choice {
        Environment::Prod => Env::Prod,
        Environment::Ref => Env::Ref,
        Environment::Test => Env::Test,
        Environment::Dev => Env::Dev,
        Environment::Auto => {
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
            return Ok((
                env,
                Some(Detection {
                    method: method.as_str(),
                    detail: found.detail,
                }),
            ));
        }
    };
    Ok((env, None))
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

/// Drives a validation whose revocation checker is [`Unchecked`]: nothing in it waits,
/// so the first poll completes and no executor is needed.
fn offline<F: Future>(future: F) -> F::Output {
    match pin!(future).poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(output) => output,
        Poll::Pending => unreachable!("offline validation does no I/O"),
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "one call site; a struct would only rename the parameters"
)]
fn report(
    source: String,
    env: Env,
    detection: Option<Detection>,
    at: Timestamp,
    ee: &Certificate,
    profile: ProfileInfo,
    result: &ValidationResult,
    mut warnings: Vec<Finding>,
) -> Report {
    warnings.extend(result.warnings.iter().map(|w| Finding {
        code: w.code.to_string(),
        subject: w.subject.clone(),
        message: w.message.clone(),
    }));
    Report {
        schema: SCHEMA,
        source,
        valid: result.valid,
        environment: EnvironmentInfo {
            name: env.as_str(),
            production: env.is_prod(),
            detection,
        },
        at: at.to_string(),
        at_ts: at,
        certificate_type: detect_certificate_type(ee).map(|t| t.to_string()),
        profile,
        revocation_checked: false,
        chain: result
            .chain
            .iter()
            .zip(&result.positions)
            .map(|(cert, position)| ChainEntry {
                position: position.as_str(),
                subject: cert.subject().to_string(),
                common_name: cert.subject_cn().to_owned(),
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
    }
}

fn document(report: &Report) -> Document {
    let mut doc = Document::default();
    doc.section("Result");
    doc.field(
        "result",
        if report.valid {
            Line::status(Tone::Good, "VALID")
        } else {
            Line::status(Tone::Bad, "INVALID")
        },
    );
    doc.field("revocation", revocation_line(report));
    let env = &report.environment;
    let mut env_line = Line::code(env.name);
    if let Some(d) = &env.detection {
        env_line = env_line.and_dim(format!(" (detected: {})", d.detail));
    }
    doc.field("environment", env_line);
    doc.field("at", when(report.at_ts));
    doc.field(
        "type",
        report
            .certificate_type
            .as_deref()
            .map_or_else(|| Line::dim("not detected"), Line::code),
    );
    doc.field("profile", profile_line(&report.profile));

    doc.section("Chain");
    if report.chain.is_empty() {
        doc.paragraph(Line::dim("no chain to a trusted root"));
    }
    for entry in &report.chain {
        doc.field(
            position_label(entry.position),
            Line::strong(&entry.common_name),
        );
    }

    if !report.errors.is_empty() {
        doc.section("Errors");
        doc.items("", report.errors.iter().map(|f| finding(Tone::Bad, f)));
        // Only a missing issuer of the end entity is fixed by --issuer; a CA without
        // its root means the roots walk did not reach one at that time.
        if report.chain.len() == 1
            && report
                .errors
                .iter()
                .any(|e| e.code == ErrorCode::ChainIncomplete.as_str())
        {
            doc.paragraph(
                Line::dim("hint: ")
                    .and_text("offline, only the roots are known; pass the issuing CA with ")
                    .and_code("--issuer"),
            );
        }
    }
    if !report.warnings.is_empty() {
        doc.section("Warnings");
        doc.items("", report.warnings.iter().map(|f| finding(Tone::Warn, f)));
    }
    doc
}

fn revocation_line(report: &Report) -> Line {
    if report.revocation_checked {
        Line::status(Tone::Good, "checked")
    } else {
        Line::status(Tone::Warn, "not checked").and_dim(" (offline)")
    }
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

fn position_label(position: &str) -> &'static str {
    match position {
        p if p == ChainPosition::EndEntity.as_str() => "end entity",
        p if p == ChainPosition::Root.as_str() => "root",
        _ => "CA",
    }
}

fn finding(tone: Tone, f: &Finding) -> Line {
    let line = Line::status(tone, &f.code);
    let line = if f.subject.is_empty() {
        line
    } else {
        line.and_text(" ").and_code(&f.subject)
    };
    line.and_text(format!(": {}", f.message))
}
