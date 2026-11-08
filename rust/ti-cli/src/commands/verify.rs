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

//! `ti pki verify`: builds the chain to the TI roots through the TSL's CAs and
//! validates it the way a relying party would, OCSP included. `--offline` uses cached
//! or embedded trust material and skips revocation, and the report says so rather than
//! passing silently.

use serde::Serialize;
use ti_client::pki::verify::{
    self as engine, Finding, OcspSettings, ProfileChoice, ProfileInfo, Reference, RevocationEntry,
    Verification, mode_name,
};
use ti_pki::profile;
use ti_pki::revocation::{RevocationMode, RevocationStatus};
use ti_pki::{Certificate, ErrorCode, ValidationResult};

use crate::cli::{GlobalArgs, VerifyArgs};
use crate::error::{CliError, Exit};
use crate::input;
use crate::output::document::{TreeRow, when};
use crate::output::{Document, Line, Output, SCHEMA, Tone};
use crate::profile::Profile;

/// The JSON document.
#[derive(Serialize)]
struct Report {
    schema: u32,
    #[serde(flatten)]
    verification: Verification,
    /// The chain as a tree, with each certificate's verdict.
    #[serde(skip)]
    tree: Vec<TreeRow>,
}

impl core::ops::Deref for Report {
    type Target = Verification;

    fn deref(&self) -> &Verification {
        &self.verification
    }
}

/// Runs the command; exit 0 when valid, 1 when not.
pub fn run(args: &VerifyArgs, global: &GlobalArgs, out: &Output) -> Result<Exit, CliError> {
    let p12_password = input::p12_password(&args.password)?;
    let (source, mut certificates) = chain_to_verify(args, &p12_password, global, out)?;
    for path in args.issuer.iter().chain(&args.intermediates) {
        let source = input::read(path)?;
        certificates.extend(
            input::certificates(&source, &p12_password)?
                .into_iter()
                .map(|loaded| loaded.certificate),
        );
    }
    let choice = match args.validation_profile.as_str() {
        profile::NONE => ProfileChoice::ChainOnly,
        profile::AUTO => ProfileChoice::Auto,
        // The value parser admits only auto, none and the profile names.
        name => ProfileChoice::Forced(
            profile::lookup(name)
                .unwrap_or_else(|| unreachable!("clap restricts --validation-profile")),
        ),
    };
    let request = engine::Request {
        source,
        certificates,
        env: args.env.concrete(),
        at: args.at,
        offline: args.offline,
        nist_only: args.nist_only,
        profile: choice,
        // A server reached by name must carry that name, unless another is given.
        expected_fqdn: args.fqdn.clone().or_else(|| {
            args.connect
                .as_ref()
                .filter(|(host, _)| host.parse::<std::net::IpAddr>().is_err())
                .map(|(host, _)| host.clone())
        }),
        ocsp_responder: args.ocsp_responder.clone(),
        ocsp_max_age: args.ocsp_max_age,
    };
    let client = crate::http::client(&global.net, out.verbosity());
    let dirs = Profile::resolve(global)?.dirs();
    let mut verification = engine::verify(&client, &dirs, &request, crate::trust::warn)?;
    for warning in &mut verification.warnings {
        if matches!(
            warning.code.as_str(),
            "profile_ambiguous" | "profile_not_detected"
        ) {
            warning.message.push_str(", pass --validation-profile");
        }
    }
    let tree = tree(&verification);
    let report = Report {
        schema: SCHEMA,
        verification,
        tree,
    };
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

/// The certificates to verify and where they came from: FILE, or the chain the
/// `--connect` server presents.
fn chain_to_verify(
    args: &VerifyArgs,
    p12_password: &str,
    global: &GlobalArgs,
    out: &Output,
) -> Result<(String, Vec<Certificate>), CliError> {
    let certificates = |source: &input::Source| -> Result<Vec<Certificate>, CliError> {
        Ok(input::certificates(source, p12_password)?
            .into_iter()
            .map(|loaded| loaded.certificate)
            .collect())
    };
    match (&args.connect, &args.file) {
        (Some((host, port)), _) => {
            let label = format!("{host}:{port}");
            let chain = crate::peer::server_chain(host, *port, &global.net)?;
            out.verbose(1, format_args!("{label}: {} certificates", chain.len()));
            let certs = chain
                .iter()
                .map(|der| Certificate::from_der(der))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|source| CliError::Certificate {
                    source_name: label.clone(),
                    source,
                })?;
            Ok((label, certs))
        }
        (None, Some(file)) => {
            let source = input::read(file)?;
            let certs = certificates(&source)?;
            Ok((source.name, certs))
        }
        (None, None) => unreachable!("clap requires FILE or --connect"),
    }
}

/// The chain as a tree: each certificate marked by the findings that concern it, with
/// what OCSP said of it.
fn tree(v: &Verification) -> Vec<TreeRow> {
    let result = &v.result;
    super::chain_tree(
        &result.chain,
        v.complete(),
        v.at_ts,
        |i| mark(result, result.chain[i].subject_cn()),
        |i| {
            v.chain
                .get(i)
                .and_then(|entry| entry.revocation.as_ref())
                .map(|r| Line::text(" · ").and_line(ocsp_line(r)))
                .unwrap_or_default()
        },
    )
}

/// ✗ for a certificate an error concerns, a yellow `!` for one only warnings concern (an
/// expired CA the Kompromissmodell accepts, `ca_expired`), ✓ otherwise.
fn mark(result: &ValidationResult, subject: &str) -> Line {
    if result.errors.iter().any(|e| e.subject == subject) {
        Line::status(Tone::Bad, "✗ ")
    } else if result.warnings.iter().any(|w| w.subject == subject) {
        Line::status(Tone::Warn, "! ")
    } else {
        Line::status(Tone::Good, "✓ ")
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
    if let Some(ocsp) = &report.ocsp {
        doc.field("ocsp", ocsp_settings_line(ocsp));
    }
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
    doc.tree(super::tsl_tree(&report.trust, report.at_ts));

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
    if let Some(ocsp) = &report.ocsp {
        doc.paragraph(Line::dim("ocsp ").and_line(ocsp_settings_line(ocsp)));
    }
    if report.insecure_transport {
        doc.paragraph(Line::status(Tone::Warn, "TLS of downloads not verified").and_dim(" (-k)"));
    }

    if report.tree.is_empty() {
        doc.items("", [Line::dim("no chain to a trusted root")]);
    }
    doc.tree(report.tree.clone());
    doc.tree(super::tsl_tree(&report.trust, report.at_ts));

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
    // Under hard-fail a failed query leaves no answer, only an error.
    let failed = report
        .errors
        .iter()
        .any(|e| e.code == ErrorCode::OcspUnavailable.as_str());
    let line = if answers.is_empty() && failed {
        Line::status(Tone::Bad, "failed").and_dim(" (no OCSP answer, see findings)")
    } else if answers.is_empty() {
        Line::status(Tone::Warn, "not checked").and_dim(" (no chain to check)")
    } else if has(RevocationStatus::Revoked)
        && !report
            .errors
            .iter()
            .any(|e| e.code == ErrorCode::Revoked.as_str())
    {
        Line::status(Tone::Warn, "revoked after the reference time")
            .and_dim(" (valid then, TUC_PKI_006 8a)")
    } else if has(RevocationStatus::Revoked) {
        Line::status(Tone::Bad, "revoked")
    } else if has(RevocationStatus::Unknown) {
        Line::status(Tone::Warn, "unknown").and_dim(" (no usable OCSP answer, see chain)")
    } else {
        // Only the end entity is asked; the CAs' standing is the TSL's (TUC_PKI_018).
        Line::status(Tone::Good, "not revoked")
            .and_dim(" (OCSP for the end entity, the CAs by the TSL)")
    };
    // A responder answers for the time it is asked; the status is judged at --at.
    let line = if report.reference == Reference::Given {
        line.and_dim(" · OCSP answered now, judged at --at")
    } else {
        line
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
        let how = r.authorization.map_or(String::new(), |a| match a {
            "tsl_listed" => ", listed in the TSL".to_owned(),
            other => format!(", {}", other.replace('_', " ")),
        });
        line = line.and_dim(format!(" by {}{how}", r.responder));
    }
    if !r.reason.is_empty() {
        line = line.and_dim(format!(": {}", r.reason));
    }
    if r.cached {
        let at = r.produced_at.as_deref().unwrap_or("earlier");
        line = line.and_dim(format!(" · cached, produced {at}"));
    }
    line
}

fn ocsp_settings_line(ocsp: &OcspSettings) -> Line {
    let responder = ocsp
        .responder_url
        .as_ref()
        .map_or_else(|| Line::text("each certificate's responder"), Line::code);
    let ms = ocsp.max_response_age_ms;
    let age = if ms.is_multiple_of(1_000) {
        format!("{}s", ms / 1_000)
    } else if ms < 1_000 {
        format!("{ms}ms")
    } else {
        let fraction = format!("{:03}", ms % 1_000);
        format!("{}.{}s", ms / 1_000, fraction.trim_end_matches('0'))
    };
    responder.and_dim(format!(" · responses up to {age} old"))
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ti_pki::tsl::Intermediate;
    use ti_pki::{Timestamp, TrustConfig, TrustStore, Validator};

    use super::*;
    use crate::output::document::Span;

    fn pki_fixture(name: &str) -> Certificate {
        let path = format!(
            "{}/../ti-pki/tests/pki/{name}.pem",
            env!("CARGO_MANIFEST_DIR")
        );
        ti_pki::parse_pem_certificates(&std::fs::read(path).unwrap())
            .unwrap()
            .remove(0)
    }

    /// The trust tree of an end entity under GEM.SubCA-Short TEST-ONLY in 2028, when the CA
    /// has expired, validated offline.
    fn trust_tree(ee: &str) -> Vec<TreeRow> {
        let at = Timestamp(1_830_297_600);
        let store = TrustStore::new([pki_fixture("rca1")]).with_intermediates(vec![Intermediate {
            certificate: pki_fixture("sub-ca-short"),
            provider: "TSP".into(),
            revoked_since: None,
        }]);
        let config = TrustConfig {
            revocation: RevocationMode::Disabled,
            ..TrustConfig::for_anchor(Vec::new())
        };
        let validator = Validator::new(&config, Arc::new(store));
        let result = ti_client::block_on(validator.validate(
            &[pki_fixture(ee)],
            at,
            &ti_pki::revocation::Unchecked,
        ))
        .unwrap();
        super::super::chain_tree(
            &result.chain,
            true,
            at,
            |i| mark(&result, result.chain[i].subject_cn()),
            |_| Line::default(),
        )
    }

    /// `ca_expired`: an expired CA the Kompromissmodell accepts is a warning in the trust
    /// tree, a yellow `!` and nothing dimmed, not a failure; under the shell model the same
    /// CA fails with ✗.
    #[test]
    fn ca_expired_is_rendered_as_a_warning_not_a_failure() {
        let rows = trust_tree("ee-short-hci-aut");
        let ca = &rows[1];
        assert_eq!(ca.name.plain(), "! GEM.SubCA-Short TEST-ONLY");
        assert_eq!(ca.name.0[0], Span::Status(Tone::Warn, "! ".into()));
        assert_eq!(
            ca.detail.plain(),
            "CA · expired 2027-01-01, accepted under the Kompromissmodell"
        );
        assert!(
            !ca.detail.0.iter().any(|s| matches!(s, Span::Dim(_))),
            "{:?}",
            ca.detail
        );
        assert_eq!(rows[0].name.0[0], Span::Status(Tone::Good, "✓ ".into()));

        let component = &trust_tree("ee-short-fd-tls-s")[1];
        assert_eq!(component.name.0[0], Span::Status(Tone::Bad, "✗ ".into()));
        assert!(
            !component.detail.plain().contains("Kompromissmodell"),
            "{:?}",
            component.detail
        );
    }
}
