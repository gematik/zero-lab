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

//! `ti pki verify --connect HOST --validation-profile web`: a TLS server's verdict, the
//! server's chain judged in the handshake under a TLS profile of `spec/pki-validation`, here
//! `web` (TLSV-040 to 045) as the web transports judge it (ti-client's
//! `peer::web_server_verdict`), reported in verify's shape.

use serde::Serialize;
use ti_client::input::Loaded;
use ti_client::peer::{StatusSource, TlsServerVerdict};
use ti_pki::{Certificate, Timestamp};

use crate::cli::{GlobalArgs, VerifyArgs};
use crate::error::{CliError, Exit};
use crate::output::document::{TreeRow, when};
use crate::output::{Document, Line, Output, SCHEMA, Tone};

/// The value of `--validation-profile` that judges a `--connect` server under the `web` TLS
/// profile.
pub const WEB: &str = "web";

/// The JSON document, `$defs/tls_server` of the schema: `tls_profile` tells it from the TI
/// report.
#[derive(Serialize)]
struct Report {
    schema: u32,
    /// `host:port`.
    server: String,
    tls_profile: &'static str,
    /// `given`, or why `auto` chose it.
    profile_reason: String,
    valid: bool,
    host: String,
    at: String,
    revocation: Revocation,
    trust: Trust,
    chain: Vec<ChainEntry>,
    /// The TLSV result code that refused the server, none when it was accepted.
    errors: Vec<Finding>,
    warnings: Vec<Finding>,
    #[serde(skip)]
    at_ts: Timestamp,
    #[serde(skip)]
    certificates: Vec<Certificate>,
}

#[derive(Serialize)]
struct Revocation {
    /// `stapled_ocsp`, `ocsp_responder`, `crl`, or `None` without a status.
    source: Option<&'static str>,
    /// Whether the server stapled a response, used or not.
    stapled: bool,
}

#[derive(Serialize)]
struct Trust {
    roots: usize,
    /// `system`, or `cacert` for `--cacert`/`--capath`.
    source: &'static str,
}

#[derive(Serialize)]
struct ChainEntry {
    position: &'static str,
    subject: String,
    common_name: String,
    not_after: String,
    pem: String,
}

/// A result code or warning of `spec/pki-validation`, and what it means here.
#[derive(Serialize)]
struct Finding {
    code: &'static str,
    message: String,
}

/// The options that belong to the TI's validation, not to `web`'s.
fn ti_only(args: &VerifyArgs) -> Option<&'static str> {
    [
        (args.offline, "--offline"),
        (args.issuer.is_some(), "--issuer"),
        (!args.intermediates.is_empty(), "--intermediates"),
        (args.nist_only, "--nist-only"),
        (args.ocsp_responder.is_some(), "--ocsp-responder"),
        (args.ocsp_max_age.is_some(), "--ocsp-max-age"),
    ]
    .into_iter()
    .find_map(|(given, name)| given.then_some(name))
}

/// Runs the command, `reason` saying why the `web` TLS profile; exit 0 when the server is
/// accepted, warnings included, 1 when not.
pub fn run(
    args: &VerifyArgs,
    global: &GlobalArgs,
    out: &Output,
    reason: String,
) -> Result<Exit, CliError> {
    if let Some(option) = ti_only(args) {
        return Err(CliError::Arguments(format!(
            "{option} applies to the TI's validation, not to the TLS profile web ({reason})"
        )));
    }
    let Some((host, port)) = &args.connect else {
        unreachable!("clap requires --connect with --validation-profile web")
    };
    let name = args.fqdn.clone().unwrap_or_else(|| host.clone());
    let at = args.at.unwrap_or_else(Timestamp::now);
    let verification =
        ti_client::peer::web_server_verdict(&global.net.net(), host, *port, &name, at)?;
    out.verbose(
        1,
        format_args!(
            "{}: {} certificates, checked as {}",
            verification.server,
            verification.chain.len(),
            verification.name
        ),
    );
    let report = report(verification, reason)?;
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

fn report(v: TlsServerVerdict, profile_reason: String) -> Result<Report, CliError> {
    let certificates = v
        .chain
        .iter()
        .map(|der| Certificate::from_der(der))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| CliError::Certificate {
            source_name: v.server.clone(),
            source,
        })?;
    let chain = certificates
        .iter()
        .enumerate()
        .map(|(i, cert)| ChainEntry {
            position: match i {
                0 => "end_entity",
                _ if cert.subject_der() == cert.issuer_der() => "root",
                _ => "sub_ca",
            },
            subject: cert.subject().to_string(),
            common_name: cert.subject_cn().to_owned(),
            not_after: cert.not_after().to_string(),
            pem: cert.to_pem(),
        })
        .collect();
    let verdict = v.verdict;
    let errors = if verdict.is_valid() {
        Vec::new()
    } else {
        vec![Finding {
            code: verdict.code.as_str(),
            message: verdict.detail.clone(),
        }]
    };
    Ok(Report {
        schema: SCHEMA,
        server: v.server,
        tls_profile: v.profile.as_str(),
        profile_reason,
        valid: verdict.is_valid(),
        host: v.name,
        at: v.at.to_string(),
        revocation: Revocation {
            source: verdict.status_source.map(StatusSource::as_str),
            stapled: v.stapled,
        },
        trust: Trust {
            roots: v.roots,
            source: if v.system_roots { "system" } else { "cacert" },
        },
        chain,
        errors,
        warnings: verdict
            .warnings
            .iter()
            .map(|code| Finding {
                code,
                message: warning_text(code).to_owned(),
            })
            .collect(),
        at_ts: v.at,
        certificates,
    })
}

impl Report {
    /// The TLSV result code: `valid`, or the one that refused the server.
    fn code(&self) -> &'static str {
        self.errors.first().map_or("valid", |e| e.code)
    }
}

/// What a warning of the profile means; both are its documented deviations.
fn warning_text(code: &str) -> &'static str {
    match code {
        "key_phased_out" => {
            "RSA key below 3000 bits, accepted under the web profile's deviation from A_28976"
        }
        "revocation_unavailable" => {
            "no source gave a revocation status, accepted under the web profile's deviation from A_27857-02"
        }
        _ => "",
    }
}

/// `VALID`, or `INVALID` with the code; and the number of warnings.
fn verdict(report: &Report) -> Line {
    let mut line = if report.valid {
        Line::status(Tone::Good, "VALID")
    } else {
        Line::status(Tone::Bad, "INVALID")
            .and_text(" ")
            .and_code(report.code())
    };
    if !report.warnings.is_empty() {
        let n = report.warnings.len();
        line = line.and_dim(format!(", {n} warning{}", if n == 1 { "" } else { "s" }));
    }
    line
}

/// Where the status came from, or why there is none.
fn revocation_line(report: &Report) -> Line {
    let stapled = if report.revocation.stapled {
        " (the server stapled a response)"
    } else {
        " (the server stapled none)"
    };
    match report.revocation.source {
        Some("stapled_ocsp") => Line::status(Tone::Good, "not revoked").and_dim(" · stapled OCSP"),
        Some("ocsp_responder") => {
            Line::status(Tone::Good, "not revoked").and_dim(format!(" · OCSP responder{stapled}"))
        }
        Some(source) => {
            Line::status(Tone::Good, "not revoked").and_dim(format!(" · {source}{stapled}"))
        }
        None if report.code() == "revoked" => Line::status(Tone::Bad, "revoked"),
        None if report.valid => Line::status(Tone::Warn, "unavailable")
            .and_dim(format!(" · no source gave a status{stapled}")),
        None => Line::dim("not checked (refused before revocation)"),
    }
}

/// `web (auto: not a TI certificate)`: the TLS profile and why, as verify's profile line.
fn profile_line(report: &Report) -> Line {
    Line::code(report.tls_profile).and_dim(format!(" ({})", report.profile_reason))
}

fn trust_line(report: &Report) -> Line {
    let roots = format!("{} roots", report.trust.roots);
    match report.trust.source {
        "system" => Line::text(roots).and_dim(" · the operating system's"),
        _ => Line::text(roots).and_dim(" · --cacert/--capath"),
    }
}

/// The chain as the server sent it, the end entity marked by the verdict and its revocation
/// beside it, then the root it reached in the trust store, or the issuer none was found for.
fn tree(report: &Report) -> Vec<TreeRow> {
    let mut rows = super::chain_tree(
        &report.certificates,
        false,
        report.at_ts,
        |i| match (i, report.valid, report.warnings.is_empty()) {
            (0, false, _) => Line::status(Tone::Bad, "✗ "),
            (0, true, false) => Line::status(Tone::Warn, "! "),
            (_, true, _) => Line::status(Tone::Good, "✓ "),
            _ => Line::dim("· "),
        },
        |i| {
            if i == 0 {
                Line::text(" · ").and_line(revocation_line(report))
            } else {
                Line::default()
            }
        },
    );
    // chain_tree ends an incomplete chain with the TI's "not among the trusted CAs"; a
    // server rarely sends its root, which the trust store holds.
    rows.pop();
    let Some(last) = report.certificates.last() else {
        return rows;
    };
    if last.subject_der() == last.issuer_der() {
        return rows;
    }
    let issuer_name = last.issuer().to_string();
    let (issuer, _) = super::inspect::split_name(&issuer_name);
    let issuer = issuer.unwrap_or_else(|| "unnamed issuer".to_owned());
    rows.push(match (report.valid, report.code()) {
        (true, _) => TreeRow {
            name: Line::status(Tone::Good, "✓ ").and_text(issuer),
            detail: Line::dim("root · in the trust store"),
        },
        (false, "chain_incomplete") => TreeRow {
            name: Line::status(Tone::Bad, "? ").and_text(issuer),
            detail: Line::status(Tone::Bad, "issuer not among the trusted roots"),
        },
        (false, _) => TreeRow {
            name: Line::dim("· ").and_text(issuer),
            detail: Line::dim("root"),
        },
    });
    rows
}

/// `error <code>: <detail>`, `warning <code>: <meaning>`.
fn findings(report: &Report) -> Vec<Line> {
    report
        .errors
        .iter()
        .map(|e| {
            Line::status(Tone::Bad, "error")
                .and_text(" ")
                .and_code(e.code)
                .and_text(format!(": {}", e.message))
        })
        .chain(report.warnings.iter().map(|w| {
            Line::status(Tone::Warn, "warning")
                .and_text(" ")
                .and_code(w.code)
                .and_text(format!(": {}", w.message))
        }))
        .collect()
}

/// The terminal view: the end entity as `pki inspect` shows it, the result, the chain and
/// the findings.
fn sections(report: &Report) -> Document {
    let mut doc = Document::default();
    if let Some(ee) = report.certificates.first() {
        let details =
            ti_client::pki::inspect::describe(&Loaded::without_key(ee.clone()), report.at_ts);
        super::inspect::certificate_sections(&mut doc, &details, report.at_ts);
    }
    doc.section("TLS server verdict");
    doc.field("result", verdict(report));
    doc.field("server", Line::code(&report.server));
    doc.field("host", Line::code(&report.host));
    doc.field("profile", profile_line(report));
    doc.field("revocation", revocation_line(report));
    doc.field("at", when(report.at_ts));
    doc.field("trust", trust_line(report));
    doc.section("Chain");
    doc.tree(tree(report));
    let findings = findings(report);
    if !findings.is_empty() {
        doc.section("Findings");
        doc.items("", findings);
    }
    doc
}

/// The Markdown view: the verdict and context as lines, the chain, the findings, the chain
/// as PEM.
fn summary(report: &Report) -> Document {
    let mut doc = Document::default();
    let mut line = verdict(report);
    if let Some(ee) = report.chain.first() {
        line = line.and_text(" · ").and_strong(&ee.common_name);
    }
    doc.paragraph(line.and_dim(" · TLS server verdict"));
    doc.paragraph(
        Line::text(&report.server)
            .and_dim(format!(" as {}", report.host))
            .and_dim(format!(" · at {}", when(report.at_ts)))
            .and_dim(" · profile ")
            .and_line(profile_line(report)),
    );
    doc.paragraph(Line::dim("revocation ").and_line(revocation_line(report)));
    doc.paragraph(Line::dim("trust ").and_line(trust_line(report)));
    doc.tree(tree(report));
    let findings = findings(report);
    if !findings.is_empty() {
        doc.section("Findings").items("", findings);
    }
    let pem: String = report.chain.iter().map(|c| c.pem.as_str()).collect();
    if !pem.is_empty() {
        doc.pem(pem);
    }
    doc
}
