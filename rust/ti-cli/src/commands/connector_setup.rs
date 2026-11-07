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

//! `ti connector config new|edit|set|pin`: creating and changing `.kon` files. On a
//! terminal the commands ask for what their options do not give; without one a missing
//! option is an error. What a file may hold, and what a change must not bring into a
//! production file, comes from `ti_connector_client::edit`, which other front ends
//! share. Files are written atomically with mode 0600; secrets are never printed.

use std::path::{Path, PathBuf};

use serde::Serialize;
use ti_client::connector::setup::{refuse, validate};
use ti_client::connector::store::{self, KonFile};
use ti_connector_client::Dotkon;
use ti_connector_client::check::{Report, Status};
use ti_connector_client::config::{self, CertificateView};
use ti_connector_client::edit::{self, NewConfig, NewCredentials};
use ti_pki::{Certificate, Timestamp};

use super::connector::emit;
use super::connector_config as configs;
use crate::cli::{
    ConfigCredentialArgs, ConfigEditArgs, ConfigNewArgs, ConfigPinArgs, ConfigPinChoice,
    ConnectorArgs, GlobalArgs,
};
use crate::error::{CliError, Exit};
use crate::output::{Line, Output, Tone};
use crate::prompt::{self, Ask};

// ---- new ----------------------------------------------------------------------------

#[derive(Serialize)]
struct NewReport<'a> {
    name: &'a str,
    path: String,
    url: &'a str,
    /// Whether the file was written.
    saved: bool,
    /// What the user should know: insecureSkipVerify, the client certificate.
    warnings: Vec<String>,
    /// The test before saving; null with --no-test.
    test: Option<&'a Report>,
}

/// `ti connector config new`.
pub fn new(
    args: &ConfigNewArgs,
    connector_args: &ConnectorArgs,
    global: &GlobalArgs,
    out: &Output,
) -> Result<Exit, CliError> {
    new_with(args, connector_args, global, out, &mut *prompt::terminal())
}

fn new_with(
    args: &ConfigNewArgs,
    connector_args: &ConnectorArgs,
    global: &GlobalArgs,
    out: &Output,
    ask: &mut dyn Ask,
) -> Result<Exit, CliError> {
    let path = store::new_path(&args.name)?;
    if path.exists() && !args.force {
        return Err(CliError::OutputExists(path.display().to_string()));
    }
    let mut warnings = Vec::new();
    let mut config = new_config(args, global, ask, &mut warnings)?;
    let (json, report, save) = loop {
        let json = config.to_json();
        refuse(None, &validate(&json)?)?;
        if args.no_test {
            break (json, None, true);
        }
        ask.say("Testing the configuration …");
        let report = configs::run_checks(&json, Some(0o600), connector_args, global, out)?;
        if report.status != Status::Fail {
            break (json, Some(report), true);
        }
        match after_failure(&report, ask)? {
            Failed::Again => call_context(&mut config, ask)?,
            Failed::Save => break (json, Some(report), true),
            Failed::Discard => break (json, Some(report), false),
        }
    };
    if save {
        store::write(&path, &json, &mut warnings)?;
    }
    let name = path
        .file_stem()
        .map_or_else(|| args.name.clone(), |s| s.to_string_lossy().into_owned());
    let shown = NewReport {
        name: &name,
        path: path.display().to_string(),
        url: &config.url,
        saved: save,
        warnings,
        test: report.as_ref(),
    };
    let exit = if save { Exit::Ok } else { Exit::Invalid };
    emit(out, exit, &shown, |doc| {
        doc.section(format!("Connector configuration {}", shown.name));
        doc.field(
            if shown.saved { "saved" } else { "not saved" },
            Line::code(&shown.path),
        );
        doc.field("url", Line::code(shown.url));
        for warning in &shown.warnings {
            doc.field("warning", Line::status(Tone::Warn, warning));
        }
        if let Some(report) = shown.test {
            configs::render_report(doc, report, shown.name);
        }
    })
}

/// The file's parts, from the options or asked for, in the order of the wizard:
/// address and environment, the server certificate, credentials, call context.
fn new_config(
    args: &ConfigNewArgs,
    global: &GlobalArgs,
    ask: &mut dyn Ask,
    warnings: &mut Vec<String>,
) -> Result<NewConfig, CliError> {
    let url = address(args.url.as_deref(), ask)?;
    ask.say(&format!("Konnektor: {url}"));
    let env = if let Some(env) = &args.env {
        env.clone()
    } else {
        let options = ["ru", "tu", "pu"].map(str::to_owned);
        options[ask.choose("Environment of the Konnektor", "--env", &options)?].clone()
    };
    let production = env == "pu";
    let not_in_production = |what: &str| {
        CliError::Arguments(format!(
            "{what} not allowed in the production environment (env pu)"
        ))
    };
    let mut insecure = args.trust.insecure_skip_verify;
    if insecure && production {
        return Err(not_in_production("insecureSkipVerify is"));
    }
    let mut trust_store = Vec::new();
    if !insecure {
        let expected_host = args.expected_host.as_deref();
        match trust(
            &url,
            expected_host,
            &args.trust.pin,
            None,
            production,
            global,
            ask,
        )? {
            Trust::Pin(der) => trust_store.push(der),
            Trust::Insecure => insecure = true,
        }
    }
    if insecure {
        warn(
            ask,
            warnings,
            "insecureSkipVerify: any server certificate is accepted",
        );
    }
    let credentials = credentials(&args.credentials, ask, warnings)?;
    if credentials == NewCredentials::None && production {
        return Err(not_in_production("credentials of type none are"));
    }
    let mandant_id = value(args.mandant.as_deref(), ask, "Mandant ID", "--mandant")?;
    let client_system_id = value(
        args.client_system.as_deref(),
        ask,
        "Client system ID",
        "--client-system",
    )?;
    let workplace_id = value(
        args.workplace.as_deref(),
        ask,
        "Workplace ID",
        "--workplace",
    )?;
    let user_id = match &args.user_id {
        Some(id) => Some(id.clone()),
        None if ask.interactive() => {
            Some(ask.line("User ID (empty for none)", "--user-id", Some(""))?)
        }
        None => None,
    }
    .filter(|id| !id.is_empty());
    Ok(NewConfig {
        url,
        env: Some(env),
        mandant_id,
        client_system_id,
        workplace_id,
        user_id,
        credentials,
        trust_store,
        insecure_skip_verify: insecure,
        expected_host: args.expected_host.clone(),
        rewrite_service_endpoints: args.rewrite_endpoints,
    })
}

enum Failed {
    Again,
    Save,
    Discard,
}

/// After a failed test: on a terminal the failures, then the choice to enter the call
/// context again and test once more, to save anyway, or to discard; without one, discard.
fn after_failure(report: &Report, ask: &mut dyn Ask) -> Result<Failed, CliError> {
    if !ask.interactive() {
        return Ok(Failed::Discard);
    }
    for step in &report.steps {
        for finding in step.findings.iter().filter(|f| f.status == Status::Fail) {
            ask.say(&format!("  {} fail: {}", step.id.as_str(), finding.message));
            if let Some(hint) = &finding.hint {
                ask.say(&format!("      {hint}"));
            }
        }
    }
    let options = [
        "enter Mandant, client system and workplace again",
        "save anyway",
        "discard",
    ]
    .map(str::to_owned);
    Ok(
        match ask.choose("The test failed. What now?", "--no-test", &options)? {
            0 => Failed::Again,
            1 => Failed::Save,
            _ => Failed::Discard,
        },
    )
}

/// The call context asked again, the values entered before as defaults.
fn call_context(config: &mut NewConfig, ask: &mut dyn Ask) -> Result<(), CliError> {
    config.mandant_id = ask.line("Mandant ID", "--mandant", Some(&config.mandant_id))?;
    config.client_system_id = ask.line(
        "Client system ID",
        "--client-system",
        Some(&config.client_system_id),
    )?;
    config.workplace_id = ask.line("Workplace ID", "--workplace", Some(&config.workplace_id))?;
    Ok(())
}

fn warn(ask: &mut dyn Ask, warnings: &mut Vec<String>, warning: &str) {
    ask.say(&format!("warning: {warning}"));
    warnings.push(warning.to_owned());
}

fn address(given: Option<&str>, ask: &mut dyn Ask) -> Result<String, CliError> {
    if let Some(given) = given {
        return edit::normalize_address(given).map_err(|e| CliError::Arguments(e.to_string()));
    }
    loop {
        let input = ask.line(
            "Konnektor address (URL, host, host:port, IP)",
            "--url",
            None,
        )?;
        match edit::normalize_address(&input) {
            Ok(url) => return Ok(url),
            Err(e) => ask.say(&format!("  {e}")),
        }
    }
}

fn value(
    given: Option<&str>,
    ask: &mut dyn Ask,
    question: &str,
    flag: &str,
) -> Result<String, CliError> {
    match given {
        Some(value) if !value.is_empty() => Ok(value.to_owned()),
        Some(_) => Err(CliError::Arguments(format!("{flag} must not be empty"))),
        None => ask.line(question, flag, None),
    }
}

// ---- trust --------------------------------------------------------------------------

enum Trust {
    Pin(Vec<u8>),
    Insecure,
}

/// The certificate to pin: from `--pin-cert`, or the server's after `--pin-sha256`
/// matched it or the user confirmed it; on a terminal, refusing it may choose
/// insecureSkipVerify instead (not for production). `current` are the pins a file has.
fn trust(
    url: &str,
    expected_host: Option<&str>,
    choice: &ConfigPinChoice,
    current: Option<&[Vec<u8>]>,
    production: bool,
    global: &GlobalArgs,
    ask: &mut dyn Ask,
) -> Result<Trust, CliError> {
    if let Some(file) = &choice.pin_cert {
        let source = crate::input::read(file)?;
        let loaded = crate::input::certificates(&source, "")?;
        let first = loaded.first().ok_or_else(|| CliError::NoCertificate {
            source_name: source.name.clone(),
        })?;
        return Ok(Trust::Pin(first.certificate.der().to_vec()));
    }
    let chain =
        ti_client::connector::server_certificate(url, expected_host, global.net.connect_timeout)
            .map_err(CliError::ServerUnreachable)?;
    let leaf = chain[0].clone();
    let sha256 = config::sha256(&leaf);
    if let Some(expected) = &choice.pin_sha256 {
        let normalize = |hex: &str| -> String {
            hex.chars()
                .filter(char::is_ascii_hexdigit)
                .collect::<String>()
                .to_ascii_uppercase()
        };
        if normalize(expected) != normalize(&sha256) {
            return Err(CliError::Arguments(format!(
                "the Konnektor presents a certificate with SHA-256 {sha256}, not {expected}; nothing pinned"
            )));
        }
        return Ok(Trust::Pin(leaf));
    }
    for pinned in current.unwrap_or_default() {
        describe(ask, "pinned", pinned);
    }
    describe(ask, "server", &leaf);
    if ask.confirm(
        "Pin this server certificate?",
        "--pin-cert or --pin-sha256",
        false,
    )? {
        return Ok(Trust::Pin(leaf));
    }
    if !production
        && current.is_none()
        && ask.confirm(
            "Accept any server certificate instead (insecureSkipVerify, test Konnektors only)?",
            "--insecure-skip-verify",
            false,
        )?
    {
        return Ok(Trust::Insecure);
    }
    Err(CliError::Arguments(
        "no certificate trusted; nothing saved".into(),
    ))
}

fn describe(ask: &mut dyn Ask, label: &str, der: &[u8]) {
    match Certificate::from_der(der) {
        Ok(certificate) => {
            let view = CertificateView::of(&certificate);
            ask.say(&format!("{label} certificate"));
            ask.say(&format!("  subject  {}", view.subject));
            ask.say(&format!("  issuer   {}", view.issuer));
            ask.say(&format!(
                "  valid    {} to {}",
                view.not_before, view.not_after
            ));
            ask.say(&format!("  SHA-256  {}", view.sha256));
        }
        Err(e) => {
            ask.say(&format!("{label} certificate (does not parse: {e})"));
            ask.say(&format!("  SHA-256  {}", config::sha256(der)));
        }
    }
}

// ---- credentials ----------------------------------------------------------------------

fn credentials(
    args: &ConfigCredentialArgs,
    ask: &mut dyn Ask,
    warnings: &mut Vec<String>,
) -> Result<NewCredentials, CliError> {
    let kind = if args.basic.is_some() {
        0
    } else if args.p12.is_some() {
        1
    } else if args.no_auth {
        2
    } else {
        let options = [
            "basic: user name and password".to_owned(),
            "pkcs12: a client certificate file (mutual TLS)".to_owned(),
            "none: no client authentication".to_owned(),
        ];
        ask.choose(
            "Client authentication",
            "--basic, --p12 or --no-auth",
            &options,
        )?
    };
    match kind {
        0 => {
            let username = value(args.basic.as_deref(), ask, "User name", "--basic")?;
            let password = match &args.password_path {
                Some(path) => crate::input::first_line(path)?,
                None => ask.secret("Password", "--password-path")?,
            };
            Ok(NewCredentials::Basic { username, password })
        }
        1 => pkcs12(args, ask, warnings),
        _ => Ok(NewCredentials::None),
    }
}

fn pkcs12(
    args: &ConfigCredentialArgs,
    ask: &mut dyn Ask,
    warnings: &mut Vec<String>,
) -> Result<NewCredentials, CliError> {
    let path = match &args.p12 {
        Some(path) => path.clone(),
        None => PathBuf::from(ask.line("PKCS#12 file", "--p12", None)?),
    };
    let source = crate::input::read(&path)?;
    if store::mode(&path).is_some_and(|m| m & 0o077 != 0) {
        warn(
            ask,
            warnings,
            &format!(
                "{}: others may read the PKCS#12 file; chmod 600 it",
                source.name
            ),
        );
    }
    let (p12, password) = loop {
        let password = match &args.p12_password_path {
            Some(file) => password_line(file)?,
            None => ask.secret("PKCS#12 password", "--p12-password-path")?,
        };
        match ti_pkcs12::decode(&source.bytes, &password) {
            Ok(p12) => break (p12, password),
            Err(e)
                if e.is_wrong_password()
                    && args.p12_password_path.is_none()
                    && ask.interactive() =>
            {
                ask.say("  wrong password");
            }
            Err(source_error) => {
                return Err(CliError::Pkcs12 {
                    source_name: source.name.clone(),
                    source: source_error,
                });
            }
        }
    };
    let data = only_one_pair(p12, &password, &source.name, args.p12_pair, ask)?
        .unwrap_or_else(|| source.bytes.clone());
    let client = config::client_certificate(&data, &password);
    if let Some(cert) = &client.certificate {
        ask.say(&format!(
            "client certificate {} until {}, {}",
            cert.subject,
            cert.not_after,
            client.key.as_deref().unwrap_or("unknown key")
        ));
        if cert.expires < Timestamp::now() {
            warn(
                ask,
                warnings,
                &format!("the client certificate expired on {}", cert.not_after),
            );
        }
    }
    if !client.key_usable {
        warn(
            ask,
            warnings,
            &format!(
                "the TLS stack cannot sign with {}; use an RSA, P-256 or P-384 client certificate",
                client.key.as_deref().unwrap_or("this key")
            ),
        );
    }
    if client.legacy_encryption() {
        warn(
            ask,
            warnings,
            &format!(
                "legacy encryption ({}); `pki pkcs12 convert` writes PBES2",
                client.encryption.join(", ")
            ),
        );
    }
    Ok(NewCredentials::Pkcs12 { data, password })
}

/// For a file with several certificates and their keys, the file with only the chosen
/// one (and the certificates without a key): the transport uses the first pair. `None`
/// for a file with one.
fn only_one_pair(
    p12: ti_pkcs12::Pkcs12,
    password: &str,
    name: &str,
    given: Option<usize>,
    ask: &mut dyn Ask,
) -> Result<Option<Vec<u8>>, CliError> {
    let pairs = p12.pairs();
    let chosen = match (pairs.len(), given) {
        (0, _) => {
            return Err(CliError::IdentityNotFound(format!(
                "{name}: no certificate with its private key"
            )));
        }
        (1, _) => return Ok(None),
        (n, Some(given)) if (1..=n).contains(&given) => given - 1,
        (n, Some(given)) => {
            return Err(CliError::Arguments(format!(
                "--p12-pair {given}: the file holds {n} certificates with their key"
            )));
        }
        (_, None) => {
            let options: Vec<String> = pairs
                .iter()
                .map(|pair| {
                    Certificate::from_der(&p12.certificates[pair.certificate].der).map_or_else(
                        |e| format!("(does not parse: {e})"),
                        |c| c.subject().to_string(),
                    )
                })
                .collect();
            ask.choose(
                "The file holds several certificates with their key; use",
                "--p12-pair",
                &options,
            )?
        }
    };
    Ok(ti_client::pkcs12::keep_pair(p12, chosen, password, name).map(Some)?)
}

/// The first line of a password file; empty is a password too (PKCS#12 allows it).
fn password_line(path: &Path) -> Result<String, CliError> {
    let source = crate::input::read(path)?;
    let text = String::from_utf8(source.bytes).map_err(|error| CliError::Read {
        source_name: source.name,
        source: std::io::Error::new(std::io::ErrorKind::InvalidData, error),
    })?;
    Ok(text.lines().next().unwrap_or_default().to_owned())
}

// ---- set ----------------------------------------------------------------------------

#[derive(Serialize)]
struct SetReport<'a> {
    name: &'a str,
    path: String,
    /// The members set, in order.
    changed: Vec<String>,
}

/// `ti connector config set KEY=VALUE …`, on the configuration of `-c` or the selected one.
pub fn set(assignments: &[String], args: &ConnectorArgs, out: &Output) -> Result<Exit, CliError> {
    let file = configs::read(None, args)?;
    let before = validate(&file.json)?;
    let mut json = file.json.clone();
    let mut changed = Vec::new();
    for assignment in assignments {
        let (key, value) = assignment.split_once('=').ok_or_else(|| {
            CliError::Arguments(format!(
                "{assignment:?}: expected KEY=VALUE; -c names the configuration"
            ))
        })?;
        json = edit::set(&json, key, value).map_err(CliError::Arguments)?;
        changed.push(key.to_owned());
    }
    let after = validate(&json)?;
    refuse(Some(&before), &after)?;
    store::write(&file.path, &json, &mut Vec::new())?;
    let report = SetReport {
        name: &file.name,
        path: file.path.display().to_string(),
        changed,
    };
    emit(out, Exit::Ok, &report, |doc| {
        doc.field("changed", Line::code(report.changed.join(", ")));
        doc.field("saved", Line::code(&report.path));
    })
}

// ---- edit ---------------------------------------------------------------------------

#[derive(Serialize)]
struct EditReport<'a> {
    name: &'a str,
    path: String,
    /// Whether the file changed.
    changed: bool,
    warnings: Vec<String>,
}

/// `ti connector config edit`: in `$EDITOR` on a terminal, or only the credentials.
pub fn edit(
    args: &ConfigEditArgs,
    connector_args: &ConnectorArgs,
    out: &Output,
) -> Result<Exit, CliError> {
    edit_with(
        args,
        connector_args,
        out,
        &mut *prompt::terminal(),
        &editor(),
    )
}

/// `$VISUAL`, else `$EDITOR`, else `vi`.
fn editor() -> String {
    ["VISUAL", "EDITOR"]
        .into_iter()
        .find_map(|name| std::env::var(name).ok().filter(|e| !e.trim().is_empty()))
        .unwrap_or_else(|| "vi".to_owned())
}

fn edit_with(
    args: &ConfigEditArgs,
    connector_args: &ConnectorArgs,
    out: &Output,
    ask: &mut dyn Ask,
    editor: &str,
) -> Result<Exit, CliError> {
    let file = existing(
        args.name
            .as_deref()
            .or(connector_args.connector_config.as_deref()),
    )?;
    let before = validate(&file.json)?;
    let mut warnings = Vec::new();
    let changed = if args.credentials.given() {
        let credentials = credentials(&args.credentials, ask, &mut warnings)?;
        let json = edit::with_credentials(&file.json, &credentials).map_err(CliError::Arguments)?;
        refuse(Some(&before), &validate(&json)?)?;
        store::write(&file.path, &json, &mut warnings)?;
        true
    } else {
        if !ask.interactive() {
            return Err(CliError::Arguments(
                "an editor needs a terminal: --basic, --p12 or --no-auth change the credentials, `connector config set` the other members".into(),
            ));
        }
        in_editor(&file, &before, ask, &mut warnings, editor)?
    };
    let report = EditReport {
        name: &file.name,
        path: file.path.display().to_string(),
        changed,
        warnings,
    };
    emit(out, Exit::Ok, &report, |doc| {
        doc.field(
            if report.changed { "saved" } else { "unchanged" },
            Line::code(&report.path),
        );
        for warning in &report.warnings {
            doc.field("warning", Line::status(Tone::Warn, warning));
        }
    })
}

/// Edits a copy (mode 0600, next to the file) until it is valid or the user gives up;
/// the file is replaced only by a valid copy.
fn in_editor(
    file: &KonFile,
    before: &Dotkon,
    ask: &mut dyn Ask,
    warnings: &mut Vec<String>,
    editor: &str,
) -> Result<bool, CliError> {
    let copy = store::editable_copy(&file.path, &file.json)?;
    let result = loop {
        if let Err(e) = run_editor(editor, &copy) {
            break Err(e);
        }
        let json = match store::read_copy(&copy) {
            Ok(json) => json,
            Err(e) => break Err(e.into()),
        };
        if json == file.json {
            break Ok(false);
        }
        let problem = match validate(&json) {
            Ok(after) => match refuse(Some(before), &after) {
                Ok(()) => None,
                Err(e) => Some(e.to_string()),
            },
            Err(e) => Some(e.to_string()),
        };
        let Some(problem) = problem else {
            break store::write(&file.path, &json, warnings)
                .map(|()| true)
                .map_err(CliError::from);
        };
        ask.say(&problem);
        match ask.confirm("Edit again? (no discards the changes)", "", true) {
            Ok(true) => {}
            Ok(false) => {
                break Err(CliError::Arguments(
                    "changes discarded; the file is unchanged".into(),
                ));
            }
            Err(e) => break Err(e),
        }
    };
    store::remove_copy(&copy);
    result
}

/// Runs `editor` (a program and its arguments, split at spaces) on `path`.
fn run_editor(editor: &str, path: &Path) -> Result<(), CliError> {
    let mut words = editor.split_whitespace();
    let program = words.next().unwrap_or("vi");
    let status = std::process::Command::new(program)
        .args(words)
        .arg(path)
        .status()
        .map_err(|e| CliError::Arguments(format!("editor {program}: {e}")))?;
    if status.success() {
        Ok(())
    } else {
        Err(CliError::Arguments(format!(
            "editor {program} exited with {status}; the file is unchanged"
        )))
    }
}

// ---- pin ----------------------------------------------------------------------------

#[derive(Serialize)]
struct PinReport<'a> {
    name: &'a str,
    path: String,
    /// Whether the pin changed.
    changed: bool,
    /// SHA-256 of the pinned certificate.
    sha256: String,
    /// insecureSkipVerify, which `config pin` leaves as it is.
    insecure_skip_verify: bool,
}

/// `ti connector config pin`.
pub fn pin(
    args: &ConfigPinArgs,
    connector_args: &ConnectorArgs,
    global: &GlobalArgs,
    out: &Output,
) -> Result<Exit, CliError> {
    pin_with(args, connector_args, global, out, &mut *prompt::terminal())
}

fn pin_with(
    args: &ConfigPinArgs,
    connector_args: &ConnectorArgs,
    global: &GlobalArgs,
    out: &Output,
    ask: &mut dyn Ask,
) -> Result<Exit, CliError> {
    let file = existing(
        args.name
            .as_deref()
            .or(connector_args.connector_config.as_deref()),
    )?;
    let dotkon = validate(&file.json)?;
    if !ti_connector_client::check::is_https(&dotkon) {
        return Err(CliError::Arguments(format!(
            "{} is http: there is no certificate to pin",
            dotkon.url
        )));
    }
    let pins = edit::pins(&dotkon);
    let production = dotkon.env.is_some_and(ti_types::Env::is_prod);
    let Trust::Pin(der) = trust(
        &dotkon.url,
        dotkon.expected_host.as_deref(),
        &args.pin,
        Some(&pins),
        production,
        global,
        ask,
    )?
    else {
        return Err(CliError::Arguments(
            "no certificate trusted; the file is unchanged".into(),
        ));
    };
    let changed = !pins.contains(&der);
    if changed {
        let json = edit::with_pin(&file.json, &der).map_err(CliError::Arguments)?;
        validate(&json)?;
        store::write(&file.path, &json, &mut Vec::new())?;
    }
    let report = PinReport {
        name: &file.name,
        path: file.path.display().to_string(),
        changed,
        sha256: config::sha256(&der),
        insecure_skip_verify: dotkon.insecure_skip_verify,
    };
    emit(out, Exit::Ok, &report, |doc| {
        doc.field(
            if report.changed {
                "pinned"
            } else {
                "already pinned"
            },
            Line::code(&report.sha256),
        );
        doc.field("path", Line::code(&report.path));
        if report.insecure_skip_verify {
            doc.field(
                "warning",
                Line::status(
                    Tone::Warn,
                    "insecureSkipVerify stays set and accepts any certificate; ",
                )
                .and_code(format!(
                    "{} connector config set {} insecureSkipVerify=false",
                    crate::BIN,
                    report.name
                )),
            );
        }
    })
}

// ---- files --------------------------------------------------------------------------

fn existing(name: Option<&str>) -> Result<KonFile, CliError> {
    configs::read(name, &ConnectorArgs::for_identity(None))
}

#[cfg(test)]
mod tests {
    use base64ct::Encoding as _;
    use clap::Parser as _;

    use super::*;
    use crate::cli::{Cli, Command, ConnectorCommand, ConnectorConfig};
    use crate::prompt::Script;

    const IDENTITY: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/identity");
    /// The server certificate pinned with --pin-cert, so that nothing is fetched.
    const PIN: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../ti-connector-client/tests/tls/server.pem"
    );

    fn dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("ti-setup-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn cli(args: &[&str]) -> Cli {
        Cli::try_parse_from(std::iter::once("ti").chain(args.iter().copied())).unwrap()
    }

    /// Runs `config new` with `args`, `script` answering.
    fn wizard(args: &[&str], script: &mut Script) -> Result<Exit, CliError> {
        let cli = cli(&[
            &["--format", "json", "connector", "config", "new"][..],
            args,
        ]
        .concat());
        let Command::Connector(connector) = &cli.command else {
            panic!("not a connector command")
        };
        let ConnectorCommand::Config(ConnectorConfig::New(new)) = &connector.command else {
            panic!("not config new")
        };
        let out = Output::new(&cli.global);
        new_with(new, &connector.args, &cli.global, &out, script)
    }

    fn kon(path: &Path) -> serde_json::Value {
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
    }

    fn said(script: &Script, text: &str) -> bool {
        script.said.iter().any(|line| line.contains(text))
    }

    #[test]
    fn the_wizard_asks_for_what_the_options_leave_out() {
        let file = dir("wizard").join("w.kon");
        let mut script = Script::new(&[
            "127.0.0.1:9",
            "1",
            "1",
            "u",
            "s3cret-pw",
            "M1",
            "C1",
            "W1",
            "",
        ]);
        let args = [file.to_str().unwrap(), "--no-test", "--pin-cert", PIN];
        assert_eq!(wizard(&args, &mut script).unwrap(), Exit::Ok);
        let kon = kon(&file);
        assert_eq!(kon["url"], "https://127.0.0.1:9");
        assert_eq!(kon["trustStore"].as_array().map(Vec::len), Some(1));
        assert_eq!(kon["env"], "ru");
        assert_eq!(
            kon["credentials"],
            serde_json::json!({"type": "basic", "username": "u", "password": "s3cret-pw"})
        );
        assert_eq!(
            (kon["mandantId"].as_str(), kon["workplaceId"].as_str()),
            (Some("M1"), Some("W1"))
        );
        assert!(kon.get("userId").is_none());
        assert!(!said(&script, "s3cret"), "the password is never said");
        assert!(script.answers.is_empty());
    }

    /// A failed test offers the call context again, the earlier answers as defaults, and
    /// tests once more; saving anyway is a choice, not the default.
    #[test]
    fn a_failed_test_asks_for_the_call_context_again() {
        let file = dir("wizard-retry").join("w.kon");
        let mut script = Script::new(&[
            "127.0.0.1:9",
            "1",
            "3",
            "M1",
            "C1",
            "W1",
            "",
            "1",
            "M2",
            "",
            "W2",
            "2",
        ]);
        let args = [file.to_str().unwrap(), "--pin-cert", PIN];
        assert_eq!(wizard(&args, &mut script).unwrap(), Exit::Ok);
        assert_eq!(
            script
                .said
                .iter()
                .filter(|l| l.as_str() == "Testing the configuration …")
                .count(),
            2
        );
        let kon = kon(&file);
        assert_eq!(
            (
                &kon["mandantId"],
                &kon["clientSystemId"],
                &kon["workplaceId"]
            ),
            (&"M2".into(), &"C1".into(), &"W2".into())
        );
        assert!(script.answers.is_empty());
    }

    /// What the options give is not asked; a missing secret file is an error, not a
    /// question.
    #[test]
    fn the_wizard_asks_nothing_the_options_give() {
        let file = dir("wizard-options").join("w.kon");
        let password = file.with_file_name("pw");
        std::fs::write(&password, "pw\n").unwrap();
        let mut script = Script::new(&[""]);
        let args = [
            file.to_str().unwrap(),
            "--no-test",
            "--pin-cert",
            PIN,
            "--url",
            "127.0.0.1:9",
            "--env",
            "tu",
            "--basic",
            "u",
            "--password-path",
            password.to_str().unwrap(),
            "--mandant",
            "M1",
            "--client-system",
            "C1",
            "--workplace",
            "W1",
        ];
        assert_eq!(wizard(&args, &mut script).unwrap(), Exit::Ok);
        let questions: Vec<&String> = script
            .said
            .iter()
            .filter(|l| l.ends_with(')') || l.contains("User ID"))
            .collect();
        assert_eq!(questions, ["User ID (empty for none)"], "{:?}", script.said);
        assert_eq!(kon(&file)["credentials"]["password"], "pw");
    }

    /// A PKCS#12 file with several certificates and their keys: the user chooses one,
    /// and only that one goes into the .kon file, since the transport uses the first.
    /// A wrong password is asked again.
    #[test]
    fn the_wizard_keeps_only_the_chosen_pair_of_a_pkcs12_file() {
        let dir = dir("wizard-p12");
        let read = |name: &str| {
            ti_pkcs12::decode(&std::fs::read(format!("{IDENTITY}/{name}")).unwrap(), "00").unwrap()
        };
        let (aut, enc) = (read("aut.p12"), read("enc.p12"));
        let mut both = aut.clone();
        both.certificates.extend(enc.certificates.clone());
        both.keys.extend(enc.keys.clone());
        assert_eq!(both.pairs().len(), 2, "the fixtures' localKeyIds differ");
        let p12 = dir.join("both.p12");
        std::fs::write(
            &p12,
            ti_client::pkcs12::encode(&both, "00", "both").unwrap(),
        )
        .unwrap();
        let file = dir.join("w.kon");
        let mut script = Script::new(&[
            "127.0.0.1:9",
            "2",
            "2",
            p12.to_str().unwrap(),
            "wrong",
            "00",
            "2",
            "M1",
            "C1",
            "W1",
            "",
        ]);
        let args = [file.to_str().unwrap(), "--no-test", "--pin-cert", PIN];
        assert_eq!(wizard(&args, &mut script).unwrap(), Exit::Ok);
        assert!(said(&script, "wrong password"), "{:?}", script.said);
        assert!(
            said(&script, "cannot sign with ECDSA brainpoolP256r1"),
            "{:?}",
            script.said
        );
        let data = kon(&file)["credentials"]["data"]
            .as_str()
            .unwrap()
            .to_owned();
        let stored =
            ti_pkcs12::decode(&base64ct::Base64::decode_vec(&data).unwrap(), "00").unwrap();
        let pairs = stored.pairs();
        assert_eq!(pairs.len(), 1);
        assert_eq!(
            stored.certificates[pairs[0].certificate].der,
            enc.certificates[enc.pairs()[0].certificate].der
        );
    }

    /// A file for pu, edited by `script` (a shell script getting the copy's path).
    #[cfg(unix)]
    fn editing(name: &str, script: &str) -> (PathBuf, String) {
        let dir = dir(name);
        let file = dir.join("e.kon");
        let config = NewConfig {
            url: "https://konnektor.test".into(),
            env: Some("pu".into()),
            mandant_id: "M1".into(),
            client_system_id: "C1".into(),
            workplace_id: "W1".into(),
            user_id: None,
            credentials: NewCredentials::Basic {
                username: "u".into(),
                password: "pw".into(),
            },
            trust_store: Vec::new(),
            insecure_skip_verify: false,
            expected_host: None,
            rewrite_service_endpoints: false,
        };
        std::fs::write(&file, config.to_json()).unwrap();
        let editor = dir.join("editor.sh");
        std::fs::write(&editor, script).unwrap();
        (file, format!("sh {}", editor.display()))
    }

    #[cfg(unix)]
    fn edit_in(file: &Path, editor: &str, script: &mut Script) -> Result<Exit, CliError> {
        let path = file.to_str().unwrap();
        let cli = cli(&["--format", "json", "connector", "config", "edit", path]);
        let Command::Connector(connector) = &cli.command else {
            panic!("not a connector command")
        };
        let ConnectorCommand::Config(ConnectorConfig::Edit(args)) = &connector.command else {
            panic!("not config edit")
        };
        edit_with(
            args,
            &connector.args,
            &Output::new(&cli.global),
            script,
            editor,
        )
    }

    #[cfg(unix)]
    /// Hidden files next to the .kon file: an edited copy or a temporary file left over.
    fn leftovers(file: &Path) -> Vec<String> {
        std::fs::read_dir(file.parent().unwrap())
            .unwrap()
            .filter_map(|e| e.ok()?.file_name().into_string().ok())
            .filter(|n| n.starts_with('.'))
            .collect()
    }

    #[cfg(unix)]
    #[test]
    fn the_editor_replaces_the_file_with_a_valid_copy() {
        use std::os::unix::fs::PermissionsExt as _;
        let (file, editor) = editing("edit-ok", "sed -i.bak 's/W1/W2/' \"$1\" && rm \"$1.bak\"\n");
        assert_eq!(
            edit_in(&file, &editor, &mut Script::new(&[])).unwrap(),
            Exit::Ok
        );
        assert_eq!(kon(&file)["workplaceId"], "W2");
        assert!(leftovers(&file).is_empty(), "{:?}", leftovers(&file));
        assert_eq!(
            std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    /// An invalid copy, or one that brings insecureSkipVerify into a pu file, never
    /// replaces the file; the user edits again or discards.
    #[cfg(unix)]
    #[test]
    fn the_editor_never_saves_an_invalid_copy() {
        for (name, change) in [
            ("edit-invalid", "printf '{}' > \"$1\"\n"),
            (
                "edit-pu",
                "sed -i.bak 's/\"workplaceId\": \"W1\"/\"workplaceId\": \"W1\", \"insecureSkipVerify\": true/' \"$1\" && rm \"$1.bak\"\n",
            ),
        ] {
            let (file, editor) = editing(name, change);
            let before = std::fs::read(&file).unwrap();
            let mut script = Script::new(&["y", "n"]);
            let result = edit_in(&file, &editor, &mut script);
            assert!(matches!(result, Err(CliError::Arguments(_))), "{name}");
            assert_eq!(std::fs::read(&file).unwrap(), before, "{name}");
            assert!(
                leftovers(&file).is_empty(),
                "{name}: {:?}",
                leftovers(&file)
            );
            let asked = script
                .said
                .iter()
                .filter(|l| l.starts_with("Edit again"))
                .count();
            assert_eq!(asked, 2, "{name}: {:?}", script.said);
        }
    }
}
