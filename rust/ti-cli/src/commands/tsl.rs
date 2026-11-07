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

//! `ti pki tsl show`: the TSL's CAs under the verified roots that signed them, and the
//! ones no verified root signed. The list is read from its signed bytes once its
//! signature, signer and `NextUpdate` verified (`spec/tsl-detached`); a CA still counts
//! only if a verified root signed it, and what is shown about a CA comes from its
//! certificate.
//!
//! `ti pki tsl verify`: a TSL file's signature and signer under the embedded TSL signer
//! CA of an environment (`spec/tsl-detached`, `spec/tsl-xmldsig` part B), offline.

use std::time::Duration;

use serde::Serialize;
use ti_client::pki::tsl::{self as engine, CaFilter, CaInfo, Files, Loaded, Overview, Verdict};
use ti_pki::{Certificate, Timestamp};

use crate::cli::{
    CaFilterArgs, GlobalArgs, TrustArgs, TslBundleArgs, TslExportArgs, TslShowArgs, TslVerifyArgs,
};
use crate::error::{CliError, Exit};
use crate::output::document::{date, when};
use crate::output::{Document, Line, Output, SCHEMA, Tone};

/// The JSON document of `ti pki tsl show`.
#[derive(Serialize)]
struct Report {
    schema: u32,
    #[serde(flatten)]
    overview: Overview,
}

/// Runs `ti pki tsl show`.
pub fn show(args: &TslShowArgs, global: &GlobalArgs, out: &Output) -> Result<Exit, CliError> {
    let loaded = load(&args.trust, global, out)?;
    let report = Report {
        schema: SCHEMA,
        overview: engine::overview(&loaded, &args.filter.filter(), args.rejected),
    };
    if out.is_json() {
        out.json(&report)?;
    } else {
        out.render(&document(&report.overview, !args.filter.ca.is_empty()))?;
    }
    Ok(Exit::Ok)
}

/// The JSON document of `ti pki tsl verify`.
#[derive(Serialize)]
struct VerifyReport {
    schema: u32,
    #[serde(flatten)]
    verdict: Verdict,
}

/// Runs `ti pki tsl verify`.
pub fn verify(args: &TslVerifyArgs, global: &GlobalArgs, out: &Output) -> Result<Exit, CliError> {
    let from_stdin = [
        Some(&args.file),
        Some(&args.signature),
        args.signer_status.as_ref(),
    ]
    .into_iter()
    .flatten()
    .filter(|path| path.as_os_str() == "-")
    .count();
    if from_stdin > 1 {
        return Err(CliError::Arguments(
            "only one of the list, its signature and its status can come from stdin".to_owned(),
        ));
    }
    let source = crate::input::read(&args.file)?;
    let signature = crate::input::read(&args.signature)?;
    let supplied_status = args
        .signer_status
        .as_deref()
        .map(crate::input::read)
        .transpose()?;
    let previous = args
        .previous
        .as_deref()
        .map(crate::input::read)
        .transpose()?;
    let files = Files {
        source: source.name,
        list: &source.bytes,
        signature: &signature.bytes,
        signer_status: supplied_status.as_ref().map(|s| s.bytes.as_slice()),
        previous: previous
            .as_ref()
            .map(|p| (p.bytes.as_slice(), p.name.as_str())),
    };
    let verdict = engine::verify(
        &files,
        args.env.concrete(),
        args.at,
        Duration::from_hours(24 * u64::from(args.grace)),
        args.offline,
        || {
            let transport = crate::http::transport(&global.net, out.verbosity())?;
            let store = crate::profile::open_cache(global)?;
            Ok::<_, CliError>((transport, store))
        },
    )?;
    let valid = verdict.result == "valid";
    let report = VerifyReport {
        schema: SCHEMA,
        verdict,
    };
    if out.is_json() {
        out.json(&report)?;
    } else {
        out.render(&verify_document(&report.verdict))?;
    }
    Ok(if valid { Exit::Ok } else { Exit::Invalid })
}

fn verify_document(report: &Verdict) -> Document {
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

/// Runs `ti pki tsl bundle`: the CAs `tsl show` keeps under the verified roots, with its
/// filters; the rejected ones never.
pub fn bundle(args: &TslBundleArgs, global: &GlobalArgs, out: &Output) -> Result<Exit, CliError> {
    super::bundle::refuse_existing(&args.bundle)?;
    let loaded = load(&args.trust, global, out)?;
    let env = loaded.env;
    let issued = issued_certificates(args, global, out)?;
    let (found, unknown) = engine::bundle(
        loaded,
        &args.filter.filter(),
        args.nist_only,
        args.with_roots,
        &issued,
    );
    for cert in unknown {
        crate::output::warning(format_args!(
            "{}: its issuer is neither a selected TSL CA nor a root of {env}",
            cert.subject_cn()
        ));
    }
    super::bundle::write(found, &args.bundle, out)
}

/// The certificates of `--connect` servers and `--cert` files, whose issuers select the
/// CAs; empty when neither is given.
fn issued_certificates(
    args: &TslBundleArgs,
    global: &GlobalArgs,
    out: &Output,
) -> Result<Vec<Certificate>, CliError> {
    let mut found = Vec::new();
    for (host, port) in &args.connect {
        let label = format!("{host}:{port}");
        let chain = crate::peer::server_chain(host, *port, &global.net)?;
        out.verbose(1, format_args!("{label}: {} certificates", chain.len()));
        for der in chain {
            found.push(
                Certificate::from_der(&der).map_err(|source| CliError::Certificate {
                    source_name: label.clone(),
                    source,
                })?,
            );
        }
    }
    for path in &args.cert {
        let source = crate::input::read(path)?;
        found.extend(
            crate::input::certificates(&source, "00")?
                .into_iter()
                .map(|loaded| loaded.certificate),
        );
    }
    Ok(found)
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
    /// The `.sig` written next to it; absent when the TSL went to stdout.
    signature_file: Option<String>,
    /// The `.ocsp` written next to it, if one could be loaded.
    signer_status_file: Option<String>,
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
    let loaded = load(&args.trust, global, out)?;
    let sha256 = loaded.sha256();
    let Loaded {
        env,
        config,
        bytes,
        meta,
        detached,
        verified,
        ..
    } = loaded;
    // The list cannot be verified later without its signature (TSLDET-013).
    let mut signature_file = None;
    let mut signer_status_file = None;
    if let Some(path) = &args.output {
        super::write_file(path, &bytes, args.force, false)?;
        let files = detached
            .as_ref()
            .ok_or_else(|| CliError::TrustLoad("the TSL came without its signature".into()))?;
        let sig = path.with_extension("sig");
        super::write_file(&sig, &files.signature, args.force, false)?;
        signature_file = Some(sig.display().to_string());
        if let Some((status, _)) = &files.signer_status {
            let ocsp = path.with_extension("ocsp");
            super::write_file(&ocsp, status, args.force, false)?;
            signer_status_file = Some(ocsp.display().to_string());
        }
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
        sha256,
        bytes: bytes.len(),
        url: config.tsl_url.to_string(),
        source: engine::source_name(&meta),
        fetched_at: meta.fetched_at.to_string(),
        output: args.output.as_ref().map(|p| p.display().to_string()),
        signature_file,
        signer_status_file,
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
        if let Some(signature) = &report.signature_file {
            doc.field("signature", Line::code(signature));
        }
        if let Some(status) = &report.signer_status_file {
            doc.field("signer status", Line::code(status));
        }
    })
}

/// The verified TSL of the environment `trust` names ([`engine::load`]).
fn load(trust: &TrustArgs, global: &GlobalArgs, out: &Output) -> Result<Loaded, CliError> {
    let env = super::concrete(trust.env, global)?;
    let session = crate::trust::session(global, trust.offline, out)?;
    Ok(engine::load(&session, env, trust.at)?)
}

impl CaFilterArgs {
    /// The filter as ti-client takes it.
    fn filter(&self) -> CaFilter {
        CaFilter {
            ca: self.ca.clone(),
            provider: self.provider.clone(),
            root: self.root.clone(),
            issues: self.issues.clone(),
        }
    }
}

fn document(report: &Overview, with_pem: bool) -> Document {
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
            match &ca.revoked_since {
                // The verified TSL's status: it decides what the CA still vouches for.
                Some(since) => {
                    super::validity_cell(ca.not_after_at, ca.validity).and_line(Line::status(
                        Tone::Warn,
                        format!(
                            " · revoked in the TSL since {}",
                            since.get(..10).unwrap_or(since)
                        ),
                    ))
                }
                None => super::validity_cell(ca.not_after_at, ca.validity),
            },
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
