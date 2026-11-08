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

//! `ti connector sign|encrypt|decrypt|comfort` and `verify signature`: documents
//! through the Konnektor's SignatureService and EncryptionService.

use std::path::{Path, PathBuf};

use serde::Serialize;
use ti_client::connector::documents::{self as engine, ComfortAction, ToSignWith};
use ti_connector_client::model::{Card, ExportedCertificate, SignatureCheck};
use ti_connector_client::types::Crypt;
use ti_connector_client::{SignatureFormat, media_type, short_text};

use super::connector::{emit, waiting};
use crate::cli::{
    ConnectorArgs, ConnectorComfort, DecryptArgs, EncryptArgs, ExportArgs, FormatArg, SignArgs,
};
use crate::connector::Session;
use crate::error::{CliError, Exit};
use crate::input;
use crate::output::{Line, Output, Tone, warning};

/// The media type of a file by its extension; a PDF to sign with PAdES is PDF/A.
fn mime_type(path: &Path, pades: bool) -> &'static str {
    let ext = path
        .extension()
        .map(|e| e.to_string_lossy().into_owned())
        .unwrap_or_default();
    media_type(&ext, pades)
}

fn is_pdf(path: &Path) -> bool {
    path.extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("pdf"))
}

/// `path` with `suffix` appended to its name: `a.pdf` + `.p7s` is `a.pdf.p7s`.
fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

/// Refuses an existing `path` before the card or the Konnektor does any work: a
/// signature made with a PIN entry must not be lost to an output conflict afterwards.
fn ensure_writable(path: &Path, force: bool) -> Result<(), CliError> {
    if !force && path.exists() {
        return Err(CliError::OutputExists(path.display().to_string()));
    }
    Ok(())
}

fn read(path: &Path) -> Result<Vec<u8>, CliError> {
    Ok(input::read(path)?.bytes)
}

// ---- sign and verify -------------------------------------------------------------

/// What `sign` does when options are left out.
struct SignPlan {
    format: SignatureFormat,
    mime: String,
    output: PathBuf,
    short_text: String,
}

impl SignPlan {
    /// PAdES for a PDF, CAdES otherwise; the media type from the extension; the output
    /// next to the input; the file name as short text.
    fn of(args: &SignArgs) -> Self {
        let format = match args.signature_format {
            Some(FormatArg::Pades) => SignatureFormat::Pades,
            Some(FormatArg::Cades) => SignatureFormat::Cades,
            None => SignatureFormat::for_document(is_pdf(&args.file)),
        };
        let pades = format == SignatureFormat::Pades;
        let output = args.output.clone().unwrap_or_else(|| {
            if pades {
                args.file.with_extension("signed.pdf")
            } else {
                with_suffix(&args.file, ".p7s")
            }
        });
        let name = args
            .file
            .file_name()
            .map(|n| n.to_string_lossy().into_owned());
        SignPlan {
            format,
            mime: args
                .mime_type
                .clone()
                .unwrap_or_else(|| mime_type(&args.file, pades).to_owned()),
            output,
            short_text: short_text(&args.short_text.clone().or(name).unwrap_or_default()),
        }
    }
}

#[derive(Serialize)]
struct SignReport<'a> {
    input: String,
    output: String,
    #[serde(flatten)]
    signed: &'a engine::Signed,
}

/// Runs `ti connector sign`.
pub fn sign(
    session: &Session,
    connector_args: &ConnectorArgs,
    args: &SignArgs,
    out: &Output,
) -> Result<Exit, CliError> {
    let document = read(&args.file)?;
    let SignPlan {
        format,
        mime,
        output,
        short_text,
    } = SignPlan::of(args);
    ensure_writable(&output, args.force)?;
    let signed = engine::sign(
        session,
        &ToSignWith {
            card: &args.card,
            document: &document,
            format,
            mime_type: &mime,
            short_text: &short_text,
            crypt: Crypt::from(args.crypt),
        },
        waiting(connector_args),
    )?;
    if let Some(texts) = &signed.warning {
        warning(format_args!("the Konnektor signed with a warning: {texts}"));
    }
    super::write_file(&output, &signed.bytes, args.force, false)?;
    let report = SignReport {
        input: args.file.display().to_string(),
        output: output.display().to_string(),
        signed: &signed,
    };
    emit(out, Exit::Ok, &report, |doc| {
        doc.field(
            "signed",
            Line::code(&report.input)
                .and_text(" → ")
                .and_code(&report.output),
        );
        doc.field("format", signed.format);
        doc.field("card", signed.card.label());
        if signed.comfort {
            doc.field("PIN", Line::status(Tone::Good, "comfort signature session"));
        }
    })
}

#[derive(Serialize)]
struct VerifySignatureReport<'a> {
    document: String,
    signature: Option<String>,
    #[serde(flatten)]
    check: &'a SignatureCheck,
}

/// Runs `ti connector verify signature`.
pub fn verify_signature(
    session: &Session,
    file: &Path,
    signature: Option<&Path>,
    mime_type_arg: Option<&str>,
    out: &Output,
) -> Result<Exit, CliError> {
    let format =
        SignatureFormat::to_verify(signature.is_some(), is_pdf(file)).ok_or_else(|| {
            CliError::ConnectorConfig(
                "a CAdES signature is detached: pass it with --signature".into(),
            )
        })?;
    let document = read(file)?;
    let detached = signature.map(read).transpose()?;
    let mime = mime_type_arg.map_or_else(
        || mime_type(file, format == SignatureFormat::Pades).to_owned(),
        str::to_owned,
    );
    let check = engine::verify_signature(session, format, &document, &mime, detached.as_deref())?;
    let valid = check.valid();
    let report = VerifySignatureReport {
        document: file.display().to_string(),
        signature: signature.map(|s| s.display().to_string()),
        check: &check,
    };
    let exit = if valid { Exit::Ok } else { Exit::Invalid };
    emit(out, exit, &report, |doc| {
        let tone = if valid { Tone::Good } else { Tone::Bad };
        let what = " · the Konnektor's check";
        doc.field("result", Line::status(tone, &check.result).and_dim(what));
        doc.field("document", Line::code(&report.document));
        if let Some(signature) = &report.signature {
            doc.field("signature", Line::code(signature));
        }
        doc.field("format", check.format);
        let when = format!(" · {}", check.timestamp_type);
        doc.field("time", Line::text(&check.timestamp).and_dim(when));
    })
}

// ---- encrypt and decrypt -----------------------------------------------------------

#[derive(Serialize)]
struct EncryptReport {
    input: String,
    output: String,
    /// The recipients' subject common names.
    recipients: Vec<String>,
    /// Needed again to decrypt.
    mime_type: String,
}

/// Runs `ti connector encrypt`.
pub fn encrypt(session: &Session, args: &EncryptArgs, out: &Output) -> Result<Exit, CliError> {
    let document = read(&args.file)?;
    let mut recipients = Vec::new();
    for path in &args.recipients {
        let source = input::read(path)?;
        let first = input::certificates(&source, &args.p12_password)?.remove(0);
        recipients.push(first.certificate);
    }
    for card in &args.recipient_cards {
        recipients.push(engine::encryption_certificate(session, card)?);
    }
    let mime = args
        .mime_type
        .clone()
        .unwrap_or_else(|| mime_type(&args.file, false).to_owned());
    let output = args
        .output
        .clone()
        .unwrap_or_else(|| with_suffix(&args.file, ".p7m"));
    ensure_writable(&output, args.force)?;
    let cms = engine::encrypt(session, &recipients, &document, &mime)?;
    super::write_file(&output, &cms, args.force, false)?;
    let report = EncryptReport {
        input: args.file.display().to_string(),
        output: output.display().to_string(),
        recipients: recipients
            .iter()
            .map(|c| c.subject_cn().to_owned())
            .collect(),
        mime_type: mime,
    };
    emit(out, Exit::Ok, &report, |doc| {
        doc.field(
            "encrypted",
            Line::code(&report.input)
                .and_text(" → ")
                .and_code(&report.output),
        );
        doc.items("for", report.recipients.iter().map(Line::strong));
        doc.field(
            "media type",
            Line::code(&report.mime_type).and_dim(" · needed again to decrypt"),
        );
    })
}

#[derive(Serialize)]
struct DecryptReport {
    input: String,
    output: String,
    card: Card,
    mime_type: String,
}

/// Runs `ti connector decrypt`.
pub fn decrypt(
    session: &Session,
    connector_args: &ConnectorArgs,
    args: &DecryptArgs,
    out: &Output,
) -> Result<Exit, CliError> {
    let cms = read(&args.file)?;
    let output = args.output.clone().unwrap_or_else(|| {
        if args
            .file
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("p7m"))
        {
            args.file.with_extension("")
        } else {
            with_suffix(&args.file, ".decrypted")
        }
    });
    let mime = args
        .mime_type
        .clone()
        .unwrap_or_else(|| mime_type(&output, false).to_owned());
    ensure_writable(&output, args.force)?;
    let decrypted = engine::decrypt(
        session,
        &args.card,
        Crypt::from(args.crypt),
        &cms,
        &mime,
        waiting(connector_args),
    )?;
    super::write_file(&output, &decrypted.bytes, args.force, true)?;
    let report = DecryptReport {
        input: args.file.display().to_string(),
        output: output.display().to_string(),
        card: decrypted.card,
        mime_type: mime,
    };
    emit(out, Exit::Ok, &report, |doc| {
        doc.field(
            "decrypted",
            Line::code(&report.input)
                .and_text(" → ")
                .and_code(&report.output),
        );
        doc.field("card", report.card.label());
        doc.field("media type", Line::code(&report.mime_type));
    })
}

// ---- comfort signature -------------------------------------------------------------

/// Runs `ti connector comfort activate|status|deactivate`.
pub fn comfort(
    session: &Session,
    connector_args: &ConnectorArgs,
    command: &ConnectorComfort,
    out: &Output,
) -> Result<Exit, CliError> {
    let (card, action) = match command {
        ConnectorComfort::Activate { card } => (card, ComfortAction::Activate),
        ConnectorComfort::Status { card } => (card, ComfortAction::Status),
        ConnectorComfort::Deactivate { card } => (card, ComfortAction::Deactivate),
    };
    let report = engine::comfort(session, card, action, waiting(connector_args))?;
    emit(out, Exit::Ok, &report, |doc| {
        doc.field("card", report.card.label());
        match report.comfort_signature {
            Some(status) => {
                let enabled = status == "ENABLED";
                let tone = if enabled { Tone::Good } else { Tone::Warn };
                doc.field("comfort", Line::status(tone, status));
            }
            None => {
                doc.field("comfort", Line::text("deactivated"));
            }
        }
        if let (Some(max), Some(duration)) = (report.max_signatures, &report.max_duration) {
            doc.field("per session", format!("up to {max} signatures, {duration}"));
        }
        if let Some(s) = &report.session {
            let left = format!(" · {} signatures, {} left", s.signatures_left, s.time_left);
            doc.field("session", Line::strong(s.mode).and_dim(left));
        }
    })
}

// ---- export ------------------------------------------------------------------------

#[derive(Serialize)]
struct ExportReport {
    card: Card,
    certificates: Vec<ExportedCertificate>,
    /// The file written; absent when the certificates went to stdout.
    output: Option<String>,
}

/// Runs `ti connector export certificate`: PEM (or DER) to stdout, whatever the output
/// format but JSON says, so `> cert.pem` works; or into a file.
pub fn export(session: &Session, args: &ExportArgs, out: &Output) -> Result<Exit, CliError> {
    if let Some(path) = &args.output {
        ensure_writable(path, args.force)?;
    }
    let export = engine::export(
        session,
        &args.card,
        args.cert_ref,
        args.crypt.map(Crypt::from),
    )?;
    let read = &export.certificates;
    let bytes: Vec<u8> = if args.der {
        read[0].certificate.der().to_vec()
    } else {
        read.iter()
            .map(|c| c.certificate.to_pem())
            .collect::<String>()
            .into_bytes()
    };
    if let Some(path) = &args.output {
        super::write_file(path, &bytes, args.force, false)?;
    } else if !out.is_json() {
        use std::io::Write as _;
        let mut stdout = std::io::stdout().lock();
        stdout.write_all(&bytes)?;
        stdout.flush()?;
        return Ok(Exit::Ok);
    }
    let report = ExportReport {
        certificates: read.iter().map(ExportedCertificate::from).collect(),
        card: export.card,
        output: args.output.as_ref().map(|p| p.display().to_string()),
    };
    emit(out, Exit::Ok, &report, |doc| {
        let saved: Vec<Line> = report
            .certificates
            .iter()
            .map(|c| Line::strong(c.cert_ref).and_text(format!(" {} {}", c.crypt, c.subject)))
            .collect();
        doc.items("saved", saved);
        if let Some(output) = &report.output {
            doc.field("to", Line::code(output));
        }
    })
}
