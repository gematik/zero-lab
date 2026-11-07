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

//! `ti connector config show|test`: a `.kon` configuration without its secrets, and its
//! test step by step. What is shown and how a step is judged comes from
//! `ti_connector_client::{config, check}`, which other front ends share.

use std::path::{Path, PathBuf};

use serde::Serialize;
use ti_client::connector::{TestOptions, UreqTransport, check_config};
use ti_connector_client::Dotkon;
use ti_connector_client::Timeouts;
use ti_connector_client::check::{Finding, Report, Status};
use ti_connector_client::config::{CertificateView, ConfigView, Secret};

use super::connector::emit;
use crate::cli::{ConnectorArgs, GlobalArgs};
use crate::connector::{self, Logged};
use crate::error::{CliError, Exit};
use crate::output::{Document, Line, Output, Tone};

/// A `.kon` file as read from disk.
pub(super) struct KonFile {
    pub name: String,
    pub path: PathBuf,
    pub json: Vec<u8>,
    pub mode: Option<u32>,
}

/// The file of `name`, else of `-c`, else of the selected configuration.
pub(super) fn read(name: Option<&str>, args: &ConnectorArgs) -> Result<KonFile, CliError> {
    let (name, _) = connector::selected(name.or(args.connector_config.as_deref()));
    let path = connector::resolve(&name)?;
    let json = std::fs::read(&path)
        .map_err(|e| CliError::ConnectorConfig(format!("{}: {e}", path.display())))?;
    Ok(KonFile {
        name,
        mode: mode(&path),
        path,
        json,
    })
}

#[cfg(unix)]
pub(super) fn mode(path: &Path) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::metadata(path).ok().map(|m| m.permissions().mode())
}

#[cfg(not(unix))]
pub(super) fn mode(_: &Path) -> Option<u32> {
    None
}

// ---- show ---------------------------------------------------------------------------

#[derive(Serialize)]
struct ShowReport<'a> {
    name: &'a str,
    path: String,
    /// The permission bits as octal, e.g. `0600`; null where there are none.
    mode: Option<String>,
    #[serde(flatten)]
    view: &'a ConfigView,
}

/// `ti connector config show`.
pub fn show(name: Option<&str>, args: &ConnectorArgs, out: &Output) -> Result<Exit, CliError> {
    let file = read(name, args)?;
    let dotkon = Dotkon::parse(&file.json)
        .map_err(|e| CliError::ConnectorConfig(format!("{}: {e}", file.path.display())))?;
    let view = ConfigView::new(&dotkon, &file.json);
    let report = ShowReport {
        name: &file.name,
        path: file.path.display().to_string(),
        mode: file.mode.map(|m| format!("{:04o}", m & 0o7777)),
        view: &view,
    };
    emit(out, Exit::Ok, &report, |doc| {
        render_show(doc, &report, file.mode);
    })
}

fn render_show(doc: &mut Document, report: &ShowReport<'_>, mode: Option<u32>) {
    let view = report.view;
    doc.section(format!("Connector configuration {}", report.name));
    doc.field("path", Line::code(&report.path));
    if let Some(text) = &report.mode {
        doc.field(
            "mode",
            if mode.is_some_and(|m| m & 0o077 != 0) {
                Line::status(Tone::Warn, format!("{text}, others may read it"))
            } else {
                Line::text(text)
            },
        );
    }
    doc.field("url", Line::code(&view.url));
    doc.field("env", Line::text(view.env.as_deref().unwrap_or("-")));
    doc.field(
        "context",
        Line::text(format!(
            "{}/{}/{}",
            view.mandant_id, view.workplace_id, view.client_system_id
        ))
        .and_dim(" (mandant/workplace/client system)"),
    );
    doc.field(
        "user id",
        Line::text(if view.user_id_set { "set" } else { "-" }),
    );
    if view.rewrite_service_endpoints {
        doc.field("endpoints", Line::text("rewritten to the host of url"));
    }
    doc.section("Credentials");
    let credentials = &view.credentials;
    doc.field(
        "type",
        match &credentials.username {
            Some(user) => Line::strong(credentials.kind).and_dim(format!(" as {user}")),
            None => Line::strong(credentials.kind),
        },
    );
    if credentials.kind != "none" {
        doc.field("password", secret(&credentials.password));
    }
    if credentials.kind == "pkcs12" {
        doc.field("data", secret(&credentials.data));
    }
    if let Some(client) = &credentials.client_certificate {
        match (&client.certificate, &client.error) {
            (_, Some(error)) => {
                doc.field("certificate", Line::status(Tone::Bad, error));
            }
            (Some(cert), None) => {
                certificate(doc, "certificate", cert);
                doc.field(
                    "key",
                    Line::text(client.key.as_deref().unwrap_or("-")).and_line(
                        if client.key_usable {
                            Line::text("")
                        } else {
                            Line::status(Tone::Bad, ", the TLS stack cannot sign with it")
                        },
                    ),
                );
                doc.field("encryption", Line::text(client.encryption.join(", ")));
            }
            (None, None) => {}
        }
    }
    doc.section("TLS");
    if view.insecure_skip_verify {
        doc.field(
            "verify",
            Line::status(Tone::Warn, "insecureSkipVerify: any certificate"),
        );
    }
    if let Some(host) = &view.expected_host {
        doc.field("expected host", Line::code(host));
    }
    for entry in &view.trust_store {
        match &entry.certificate {
            Some(cert) => certificate(doc, entry.role, cert),
            None => {
                doc.field(entry.role, Line::status(Tone::Bad, "does not parse"));
            }
        }
    }
    if view.trust_store.is_empty() && !view.insecure_skip_verify {
        doc.field(
            "trust",
            Line::status(Tone::Warn, "no pin: the operating system's trust store"),
        );
    }
    if !view.variables.is_empty() {
        doc.section("Environment");
        doc.field("variables", Line::code(view.variables.join(", ")));
    }
}

fn secret(secret: &Secret) -> Line {
    match secret.stored {
        "plain" => Line::status(Tone::Warn, "in the file (plain text)"),
        "environment" => Line::text("from ").and_code(
            secret
                .variables
                .iter()
                .map(|v| format!("${{{v}}}"))
                .collect::<Vec<_>>()
                .join(" "),
        ),
        _ => Line::dim("-"),
    }
}

fn certificate(doc: &mut Document, label: &str, cert: &CertificateView) {
    doc.items(
        label,
        [
            Line::text(&cert.subject).and_dim(format!(" until {}", cert.not_after)),
            Line::dim(format!("SHA-256 {}", cert.sha256)),
        ],
    );
}

// ---- test ---------------------------------------------------------------------------

#[derive(Serialize)]
struct TestReport<'a> {
    name: &'a str,
    path: String,
    #[serde(flatten)]
    report: &'a Report,
}

/// `ti connector config test`: exit 1 if a step fails.
pub fn test(
    name: Option<&str>,
    args: &ConnectorArgs,
    global: &GlobalArgs,
    out: &Output,
) -> Result<Exit, CliError> {
    let file = read(name, args)?;
    let agent = ti_client::connector::agent_config(&global.net.net())?;
    let report = run_checks(&file.json, file.mode, args, global, agent, out);
    let exit = if report.status == Status::Fail {
        Exit::Invalid
    } else {
        Exit::Ok
    };
    let shown = TestReport {
        name: &file.name,
        path: file.path.display().to_string(),
        report: &report,
    };
    emit(out, exit, &shown, |doc| {
        doc.section(format!("Test of {}", shown.name));
        doc.field("path", Line::code(&shown.path));
        render_report(doc, &report, shown.name);
    })
}

/// The steps of `report` and its result; an action names the command that does it for
/// the configuration `name`.
pub(super) fn render_report(doc: &mut Document, report: &Report, name: &str) {
    doc.section("Steps");
    for step in &report.steps {
        let mut lines = Vec::new();
        for finding in &step.findings {
            lines.push(finding_line(finding));
            if let Some(hint) = &finding.hint
                && finding.status >= Status::Warn
            {
                lines.push(Line::dim(format!("      {hint}")));
            }
            if finding.action == Some("renew_pin") {
                lines.push(
                    Line::dim("      ")
                        .and_code(format!("{} connector config pin {name}", crate::BIN)),
                );
            }
        }
        doc.items(step.id.as_str(), lines);
    }
    doc.section("Result");
    doc.paragraph(match report.status {
        Status::Fail => Line::status(Tone::Bad, "fail"),
        Status::Warn => Line::status(Tone::Warn, "works, with warnings"),
        Status::Ok | Status::Skip => Line::status(Tone::Good, "ok"),
    });
}

/// Runs the checks of `json` against the Konnektor it names.
pub(super) fn run_checks(
    json: &[u8],
    mode: Option<u32>,
    args: &ConnectorArgs,
    global: &GlobalArgs,
    agent: ureq::config::ConfigBuilder<ureq::typestate::AgentScope>,
    out: &Output,
) -> Report {
    let options = TestOptions {
        connect_timeout: global.net.connect_timeout,
        timeouts: Timeouts {
            short: args.connector_timeout,
            long: args.card_timeout,
        },
        now: ti_pki::Timestamp::now(),
        through_proxy: connector::explicit_proxy(global).is_some(),
    };
    check_config(
        json,
        mode,
        |name| std::env::var(name).ok(),
        |dotkon| UreqTransport::new(dotkon, agent).map(|t| Logged::new(t, out)),
        options,
    )
}

pub(super) fn finding_line(finding: &Finding) -> Line {
    let word = match finding.status {
        Status::Ok => Line::status(Tone::Good, "ok  "),
        Status::Warn => Line::status(Tone::Warn, "warn"),
        Status::Fail => Line::status(Tone::Bad, "fail"),
        Status::Skip => Line::dim("skip"),
    };
    word.and_text(format!("  {}", finding.message))
}
