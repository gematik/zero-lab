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
use ti_connector_client::types::{Card, CardType, CertRef, Crypt, VerificationResult};
use ti_connector_client::{ComfortUserId, Error, SignatureFormat, ToSign};

use super::connector::{CardInfo, call, card_call, card_label, emit, find};
use crate::block::block_on;
use crate::cli::{
    ConnectorArgs, ConnectorComfort, CryptArg, DecryptArgs, EncryptArgs, ExportArgs, FormatArg,
    SignArgs,
};
use crate::connector::Session;
use crate::error::{CliError, Exit, StoreFile};
use crate::input;
use crate::output::{Line, Output, Tone, Waiting, pem, warning};
use crate::paths;
use crate::store::now;
use crate::store::profile::{ProfileStore, Selected};
use ti_store::store::StoreError;
use ti_store::store::registry::COMFORT;

/// The media type of a file by its extension; a PDF to sign with PAdES is PDF/A.
fn mime_type(path: &Path, pdfa: bool) -> &'static str {
    let ext = path
        .extension()
        .map(|e| e.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    match ext.as_str() {
        "pdf" if pdfa => "application/pdf-a",
        "pdf" => "application/pdf",
        "txt" => "text/plain",
        "xml" => "text/xml",
        "json" => "application/json",
        "html" | "htm" => "text/html",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "p7s" | "p7m" => "application/pkcs7-mime",
        _ => "application/octet-stream",
    }
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

fn random(bytes: &mut [u8]) {
    rustls::crypto::ring::default_provider()
        .secure_random
        .fill(bytes)
        .expect("the operating system provides randomness");
}

// ---- comfort signature sessions ---------------------------------------------------

/// The user IDs of comfort signature sessions, sealed in the profile's state under the
/// connector configuration and the card's ICCSN. An ID lets anyone with the same call
/// context sign without a PIN while its session lasts, so it is kept only with a keyring.
/// Files of earlier versions are read while the profile has none, and moved into the
/// store once it has one.
struct ComfortStore<'a> {
    selected: &'a Selected,
    store: Option<ProfileStore>,
    config: String,
    legacy: Option<PathBuf>,
}

impl<'a> ComfortStore<'a> {
    fn open(session: &'a Session) -> Result<Self, CliError> {
        let selected = &session.selected;
        let store = if selected.has_keyring() {
            Some(selected.open_state()?)
        } else {
            None
        };
        let dir_name: String = session
            .name
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || "-_.".contains(c) {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        Ok(ComfortStore {
            selected,
            store,
            config: session.name.clone(),
            legacy: paths::legacy_state_dir()
                .ok()
                .map(|dir| dir.join("comfort").join(dir_name)),
        })
    }

    /// Keyed by ICCSN: a card handle changes when the card is inserted again.
    fn card_id(card: &Card) -> &str {
        card.iccsn.as_deref().unwrap_or(&card.card_handle)
    }

    fn id(&self, card: &Card) -> String {
        format!("{}/{}", self.config, Self::card_id(card))
    }

    fn legacy_path(&self, card: &Card) -> Option<PathBuf> {
        self.legacy
            .as_ref()
            .map(|dir| dir.join(Self::card_id(card)))
    }

    fn fail(&self, error: StoreError) -> CliError {
        CliError::Store {
            profile: self.selected.profile.name.clone(),
            file: StoreFile::Record,
            path: "comfort".into(),
            error,
        }
    }

    /// Activating needs a place to keep the new ID: checked before the card is asked.
    fn require_keyring(&self) -> Result<(), CliError> {
        match self.store {
            Some(_) => Ok(()),
            None => Err(self.fail(StoreError::NoKeyring)),
        }
    }

    fn load(&self, card: &Card) -> Result<Option<ComfortUserId>, CliError> {
        let legacy = || {
            let path = self.legacy_path(card)?;
            let text = std::fs::read_to_string(path).ok()?;
            ComfortUserId::parse(text.trim())
        };
        let Some(store) = &self.store else {
            return Ok(legacy());
        };
        match block_on(store.get(&COMFORT, self.id(card).as_bytes(), now())) {
            Ok(stored) => Ok(std::str::from_utf8(&stored.payload)
                .ok()
                .and_then(ComfortUserId::parse)),
            Err(StoreError::NotFound) => match legacy() {
                Some(user) => {
                    self.save(card, &user)?;
                    Ok(Some(user))
                }
                None => Ok(None),
            },
            Err(error) => Err(self.fail(error)),
        }
    }

    fn save(&self, card: &Card, user: &ComfortUserId) -> Result<(), CliError> {
        let Some(store) = &self.store else {
            return Err(self.fail(StoreError::NoKeyring));
        };
        block_on(store.put(
            &COMFORT,
            self.id(card).as_bytes(),
            user.as_str().as_bytes(),
            &[("konnektor", self.config.as_bytes())],
            None,
            now(),
        ))
        .map_err(|error| self.fail(error))?;
        if let Some(path) = self.legacy_path(card) {
            let _ = std::fs::remove_file(path);
        }
        Ok(())
    }

    /// Whether an ID was stored.
    fn remove(&self, card: &Card) -> Result<bool, CliError> {
        let legacy = self
            .legacy_path(card)
            .is_some_and(|path| std::fs::remove_file(path).is_ok());
        let Some(store) = &self.store else {
            return Ok(legacy);
        };
        let id = self.id(card);
        let stored = match block_on(store.get(&COMFORT, id.as_bytes(), now())) {
            Ok(_) => true,
            Err(StoreError::NotFound) => false,
            Err(error) => return Err(self.fail(error)),
        };
        block_on(store.delete(&COMFORT, id.as_bytes())).map_err(|error| self.fail(error))?;
        Ok(stored || legacy)
    }
}

/// The comfort session's user ID for `card`: `--comfort-user-id`, else the stored one.
fn comfort_user(
    args: &ConnectorArgs,
    store: &ComfortStore<'_>,
    card: &Card,
) -> Result<Option<ComfortUserId>, CliError> {
    match args.comfort_user_id.as_deref() {
        Some(text) => ComfortUserId::parse(text)
            .map(Some)
            .ok_or_else(|| CliError::ConnectorConfig("--comfort-user-id is not a UUID".into())),
        None => store.load(card),
    }
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
            None if is_pdf(&args.file) => SignatureFormat::Pades,
            Some(FormatArg::Cades) | None => SignatureFormat::Cades,
        };
        let pades = format == SignatureFormat::Pades;
        let output = args.output.clone().unwrap_or_else(|| {
            if pades {
                args.file.with_extension("signed.pdf")
            } else {
                with_suffix(&args.file, ".p7s")
            }
        });
        // The Konnektor's schema allows 30 characters.
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
            short_text: args
                .short_text
                .clone()
                .or(name)
                .unwrap_or_default()
                .chars()
                .take(30)
                .collect(),
        }
    }
}

#[derive(Serialize)]
struct SignReport {
    input: String,
    output: String,
    /// `cades` or `pades`.
    format: &'static str,
    card: CardInfo,
    /// Signed within a comfort signature session, without a PIN entry.
    comfort: bool,
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
    let pades = format == SignatureFormat::Pades;
    ensure_writable(&output, args.force)?;
    let card = find(session, &args.card)?;
    let store = ComfortStore::open(session)?;
    let user = comfort_user(connector_args, &store, &card)?;
    let message = match (card.card_type, &user) {
        (CardType::Hba, None) => "Enter PIN.QES at the card terminal",
        _ => "Signing with the card",
    };
    let signatures = session.connector.signatures();
    // The card terminal shows the job number at PIN entry; showing it here lets the user
    // match the prompt to this job.
    let job_number = call(signatures.job_number())?;
    let detail = format!("{} · job {job_number}", card_label(&card));
    let waiting = Waiting::start(message, &detail, connector_args.card_timeout);
    let signatures = match &user {
        Some(user) => signatures.as_user(user),
        None => signatures,
    };
    let crypt = Crypt::from(args.crypt);
    let signed = card_call(
        &card,
        signatures.sign_in_job(
            &job_number,
            &card.card_handle,
            format,
            Some(crypt),
            &[ToSign {
                content: &document,
                mime_type: &mime,
                short_text: Some(&short_text),
            }],
        ),
    );
    drop(waiting);
    let signed = signed?
        .into_iter()
        .next()
        .ok_or_else(|| CliError::Connector(Error::Decode("SignDocument: no result".into())))?;
    if let Some(error) = &signed.status.error {
        let texts: Vec<String> = error
            .trace
            .iter()
            .map(|t| format!("{} {}", t.code, t.error_text))
            .collect();
        warning(format_args!(
            "the Konnektor signed with a warning: {}",
            texts.join("; ")
        ));
    }
    let bytes = if pades {
        signed.signed_document
    } else {
        signed.signature
    };
    let bytes = bytes.ok_or_else(|| {
        CliError::Connector(Error::Decode(
            "SignDocument: no signature in the response".into(),
        ))
    })?;
    super::write_file(&output, &bytes, args.force, false)?;
    let report = SignReport {
        input: args.file.display().to_string(),
        output: output.display().to_string(),
        format: format.as_str(),
        card: CardInfo::from(&card),
        comfort: user.is_some(),
    };
    emit(out, Exit::Ok, &report, |doc| {
        doc.field(
            "signed",
            Line::code(&report.input)
                .and_text(" → ")
                .and_code(&report.output),
        );
        doc.field("format", report.format);
        doc.field("card", card_label(&card));
        if report.comfort {
            doc.field("PIN", Line::status(Tone::Good, "comfort signature session"));
        }
    })
}

#[derive(Serialize)]
struct VerifySignatureReport {
    document: String,
    signature: Option<String>,
    format: &'static str,
    /// `VALID`, `INCONCLUSIVE` or `INVALID`.
    result: String,
    /// What the verification time is based on, e.g. `SIGNATURE_EMBEDDED_TIMESTAMP`.
    timestamp_type: String,
    timestamp: String,
}

/// Runs `ti connector verify signature`.
pub fn verify_signature(
    session: &Session,
    file: &Path,
    signature: Option<&Path>,
    mime_type_arg: Option<&str>,
    out: &Output,
) -> Result<Exit, CliError> {
    let format = match signature {
        Some(_) => SignatureFormat::Cades,
        None if is_pdf(file) => SignatureFormat::Pades,
        None => {
            return Err(CliError::ConnectorConfig(
                "a CAdES signature is detached: pass it with --signature".into(),
            ));
        }
    };
    let document = read(file)?;
    let detached = signature.map(read).transpose()?;
    let mime = mime_type_arg.map_or_else(
        || mime_type(file, format == SignatureFormat::Pades).to_owned(),
        str::to_owned,
    );
    let verdict = call(session.connector.signatures().verify(
        format,
        &document,
        &mime,
        detached.as_deref(),
    ))?;
    let result = verdict.verification_result;
    let valid = result.high_level_result == VerificationResult::Valid.as_str();
    let report = VerifySignatureReport {
        document: file.display().to_string(),
        signature: signature.map(|s| s.display().to_string()),
        format: format.as_str(),
        result: result.high_level_result,
        timestamp_type: result.timestamp_type,
        timestamp: result.timestamp,
    };
    let exit = if valid { Exit::Ok } else { Exit::Invalid };
    emit(out, exit, &report, |doc| {
        let tone = if valid { Tone::Good } else { Tone::Bad };
        let what = " · the Konnektor's check";
        doc.field("result", Line::status(tone, &report.result).and_dim(what));
        doc.field("document", Line::code(&report.document));
        if let Some(signature) = &report.signature {
            doc.field("signature", Line::code(signature));
        }
        doc.field("format", report.format);
        let when = format!(" · {}", report.timestamp_type);
        doc.field("time", Line::text(&report.timestamp).and_dim(when));
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
        let card = find(session, card)?;
        let certificates = session.connector.certificates();
        let read = card_call(
            &card,
            certificates.read(&card.card_handle, Crypt::Ecc, &[CertRef::CEnc]),
        )?;
        let enc = read
            .into_iter()
            .next()
            .ok_or_else(|| CliError::NoCertificate {
                source_name: format!("C.ENC ECC of {}", card_label(&card)),
            })?;
        recipients.push(enc.certificate);
    }
    let ders: Vec<&[u8]> = recipients.iter().map(ti_pki::Certificate::der).collect();
    let mime = args
        .mime_type
        .clone()
        .unwrap_or_else(|| mime_type(&args.file, false).to_owned());
    let output = args
        .output
        .clone()
        .unwrap_or_else(|| with_suffix(&args.file, ".p7m"));
    ensure_writable(&output, args.force)?;
    let cms = call(
        session
            .connector
            .encryption()
            .encrypt(&ders, &document, &mime),
    )?;
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
    card: CardInfo,
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
    let card = find(session, &args.card)?;
    let waiting = Waiting::start(
        "Decrypting with the card",
        &card_label(&card),
        connector_args.card_timeout,
    );
    let crypt = Crypt::from(args.crypt);
    let plain = card_call(
        &card,
        session
            .connector
            .encryption()
            .decrypt(&card.card_handle, Some(crypt), &cms, &mime),
    );
    drop(waiting);
    super::write_file(&output, &plain?, args.force, true)?;
    let report = DecryptReport {
        input: args.file.display().to_string(),
        output: output.display().to_string(),
        card: CardInfo::from(&card),
        mime_type: mime,
    };
    emit(out, Exit::Ok, &report, |doc| {
        doc.field(
            "decrypted",
            Line::code(&report.input)
                .and_text(" → ")
                .and_code(&report.output),
        );
        doc.field("card", card_label(&card));
        doc.field("media type", Line::code(&report.mime_type));
    })
}

// ---- comfort signature -------------------------------------------------------------

#[derive(Serialize)]
struct ComfortReport {
    card: CardInfo,
    /// `ENABLED` or `DISABLED`: whether the HBA allows comfort signature.
    comfort_signature: Option<&'static str>,
    /// Signatures a session allows at most.
    max_signatures: Option<i64>,
    /// How long a session lasts, as the Konnektor states it (e.g. `PT24H`).
    max_duration: Option<String>,
    /// The session of the stored user ID, if one is active.
    session: Option<ComfortSession>,
    /// A user ID for this card is stored (`activate`) or was removed (`deactivate`).
    user_id_stored: bool,
}

#[derive(Serialize)]
struct ComfortSession {
    /// `COMFORT` or `PIN`.
    mode: &'static str,
    signatures_left: i64,
    time_left: String,
}

/// Runs `ti connector comfort activate|status|deactivate`.
pub fn comfort(
    session: &Session,
    connector_args: &ConnectorArgs,
    command: &ConnectorComfort,
    out: &Output,
) -> Result<Exit, CliError> {
    let (ConnectorComfort::Activate { card }
    | ConnectorComfort::Status { card }
    | ConnectorComfort::Deactivate { card }) = command;
    let card = find(session, card)?;
    let store = ComfortStore::open(session)?;
    let signatures = session.connector.signatures();
    let mut report = ComfortReport {
        card: CardInfo::from(&card),
        comfort_signature: None,
        max_signatures: None,
        max_duration: None,
        session: None,
        user_id_stored: false,
    };
    match command {
        ConnectorComfort::Activate { .. } => {
            store.require_keyring()?;
            // A new random user ID for each activation (A_21528), unique among the
            // Konnektor's last 1,000 operations (A_20074).
            let user = ComfortUserId::generate(|b| random(b));
            let waiting = Waiting::start(
                "Enter PIN.QES at the card terminal to activate comfort signature",
                &card_label(&card),
                connector_args.card_timeout,
            );
            let activated = card_call(&card, signatures.activate_comfort(&card.card_handle, &user));
            drop(waiting);
            activated?;
            store.save(&card, &user)?;
            report.user_id_stored = true;
            fill_mode(&mut report, &card, &signatures, &user)?;
        }
        ConnectorComfort::Status { .. } => {
            // Without a stored session the mode is asked with a fresh ID: whether
            // comfort signature is enabled does not depend on it.
            let stored = comfort_user(connector_args, &store, &card)?;
            report.user_id_stored = stored.is_some();
            let user = stored.unwrap_or_else(|| ComfortUserId::generate(|b| random(b)));
            fill_mode(&mut report, &card, &signatures, &user)?;
        }
        ConnectorComfort::Deactivate { .. } => {
            card_call(&card, signatures.deactivate_comfort(&[&card.card_handle]))?;
            report.user_id_stored = !store.remove(&card)?;
        }
    }
    emit(out, Exit::Ok, &report, |doc| {
        doc.field("card", card_label(&card));
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
        doc.field(
            "user ID stored",
            if report.user_id_stored { "yes" } else { "no" },
        );
    })
}

fn fill_mode<T: ti_connector_client::Transport>(
    report: &mut ComfortReport,
    card: &Card,
    signatures: &ti_connector_client::Signatures<'_, T>,
    user: &ComfortUserId,
) -> Result<(), CliError> {
    let mode = card_call(card, signatures.mode(&card.card_handle, user))?;
    report.comfort_signature = Some(mode.comfort_signature_status.as_str());
    report.max_signatures = Some(mode.comfort_signature_max);
    report.max_duration = Some(mode.comfort_signature_timer);
    report.session = mode.session_info.map(|s| ComfortSession {
        mode: s.signature_mode.as_str(),
        signatures_left: s.count_remaining,
        time_left: s.time_remaining,
    });
    Ok(())
}

// ---- export ------------------------------------------------------------------------

#[derive(Serialize)]
struct ExportReport {
    card: CardInfo,
    certificates: Vec<ExportedCertificate>,
    /// The file written; absent when the certificates went to stdout.
    output: Option<String>,
}

#[derive(Serialize)]
struct ExportedCertificate {
    cert_ref: &'static str,
    crypt: &'static str,
    subject: String,
    pem: String,
}

/// Runs `ti connector export certificate`: PEM (or DER) to stdout, whatever the output
/// format but JSON says, so `> cert.pem` works; or into a file.
pub fn export(session: &Session, args: &ExportArgs, out: &Output) -> Result<Exit, CliError> {
    if let Some(path) = &args.output {
        ensure_writable(path, args.force)?;
    }
    let card = find(session, &args.card)?;
    let certificates = session.connector.certificates();
    let handle = &card.card_handle;
    let read = match (args.cert_ref, args.crypt) {
        (Some(cert_ref), crypt) => {
            let crypt = Crypt::from(crypt.unwrap_or(CryptArg::Ecc));
            card_call(&card, certificates.read(handle, crypt, &[cert_ref]))?
        }
        (None, Some(crypt)) => {
            let refs = ti_connector_client::cert_refs(card.card_type).unwrap_or_default();
            card_call(&card, certificates.read(handle, crypt.into(), refs))?
        }
        (None, None) => card_call(&card, certificates.read_all(handle, card.card_type))?,
    };
    if read.is_empty() {
        return Err(CliError::NoCertificate {
            source_name: format!("the requested certificates of {}", card_label(&card)),
        });
    }
    let bytes: Vec<u8> = if args.der {
        read[0].certificate.der().to_vec()
    } else {
        read.iter()
            .map(|c| pem(c.certificate.der()))
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
        card: CardInfo::from(&card),
        certificates: read
            .iter()
            .map(|c| ExportedCertificate {
                cert_ref: c.cert_ref.as_str(),
                crypt: c.crypt.as_str(),
                subject: c.certificate.subject_cn().to_owned(),
                pem: pem(c.certificate.der()),
            })
            .collect(),
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
