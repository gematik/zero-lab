//! `ti identity inspect` and `ti identity sign`: the SMC-B identity the way an ePA
//! client or an IDP Authenticator-Modul needs it, whichever source holds the key.

use base64ct::{Base64UrlUnpadded, Encoding};
use jwz::header::HeaderParams;
use jwz::jwa::SignatureAlgorithm;
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use ti_pki::load::SystemClock;
use ti_pki::{Certificate, Clock};

use crate::cli::{GlobalArgs, IdentityArgs, IdentitySignArgs};
use crate::error::{CliError, Exit};
use crate::identity::{Identity, SourceKind};
use crate::input;
use crate::output::{Document, Line, Output, SCHEMA, hex};

/// `ti identity inspect` as JSON.
#[derive(Serialize)]
struct InspectReport {
    schema: u32,
    source: SourceInfo,
    telematik_id: Option<String>,
    signing: Signing,
    certificate: ti_report::CertificateInfo,
    chain: Vec<ti_report::CertificateInfo>,
}

#[derive(Serialize)]
struct SourceInfo {
    kind: SourceKind,
    name: String,
}

#[derive(Serialize)]
struct Signing {
    alg: &'static str,
    curve: &'static str,
}

/// `ti identity sign` as JSON.
#[derive(Serialize)]
struct SignReport {
    schema: u32,
    jws: String,
    alg: &'static str,
    /// The protected header as sent.
    header: Value,
    identity: IdentityInfo,
}

#[derive(Serialize)]
struct IdentityInfo {
    subject: String,
    telematik_id: Option<String>,
    sha256: String,
}

fn source_info(identity: &Identity) -> SourceInfo {
    SourceInfo {
        kind: identity.kind,
        name: identity.name.clone(),
    }
}

fn fingerprint(cert: &Certificate) -> String {
    hex(&Sha256::digest(cert.der()))
}

/// Runs `ti identity inspect`.
pub fn inspect(args: &IdentityArgs, global: &GlobalArgs, out: &Output) -> Result<Exit, CliError> {
    let identity = Identity::load(args, global, out)?;
    let now = SystemClock.now();
    let report = InspectReport {
        schema: SCHEMA,
        source: source_info(&identity),
        telematik_id: identity.telematik_id(),
        signing: Signing {
            alg: "ES256",
            curve: identity.curve.name(),
        },
        certificate: ti_report::describe(&identity.certificate, now),
        chain: identity
            .chain
            .iter()
            .map(|cert| ti_report::describe(cert, now))
            .collect(),
    };
    if out.is_json() {
        out.json(&report)?;
        return Ok(Exit::Ok);
    }
    let mut doc = Document::default();
    doc.title(identity.certificate.subject_cn());
    doc.field(
        "Telematik-ID",
        report
            .telematik_id
            .as_deref()
            .map_or_else(|| Line::dim("none in the certificate"), Line::code),
    );
    doc.field("subject", Line::text(&report.certificate.subject));
    doc.field("issuer", Line::text(&report.certificate.issuer));
    doc.field(
        "validity",
        super::validity_cell(
            identity.certificate.not_after(),
            report.certificate.validity,
        ),
    );
    doc.field(
        "key",
        Line::text(&report.certificate.key.algorithm)
            .and_dim(format!(" · signs {}", report.signing.alg)),
    );
    doc.field(
        "key usage",
        Line::text(report.certificate.key_usage.join(", ")),
    );
    doc.field(
        "source",
        Line::text(format!(
            "{}: ",
            serde_json::to_value(report.source.kind)?
                .as_str()
                .unwrap_or("?")
        ))
        .and_code(&report.source.name),
    );
    if !report.chain.is_empty() {
        doc.items(
            "found with it",
            report
                .chain
                .iter()
                .map(|c| Line::text(&c.subject))
                .collect::<Vec<Line>>(),
        );
    }
    if out.is_markdown() {
        doc.pem(&report.certificate.pem);
    }
    out.render(&doc)?;
    Ok(Exit::Ok)
}

/// Runs `ti identity sign`.
pub fn sign(args: &IdentitySignArgs, global: &GlobalArgs, out: &Output) -> Result<Exit, CliError> {
    let claims = read_claims(&args.claims)?;
    let params = header_params(args)?;
    let identity = Identity::load(&args.identity, global, out)?;
    let payload = serde_json::to_vec(&claims)?;
    let alg = SignatureAlgorithm::from(args.alg);
    let jws = identity.sign(&payload, params, alg)?;
    let header = protected_header(&jws)?;
    let report = SignReport {
        schema: SCHEMA,
        alg: alg.as_str(),
        header,
        identity: IdentityInfo {
            subject: identity.certificate.subject().to_string(),
            telematik_id: identity.telematik_id(),
            sha256: fingerprint(&identity.certificate),
        },
        jws,
    };
    if out.is_json() {
        out.json(&report)?;
        return Ok(Exit::Ok);
    }
    let mut doc = Document::default();
    doc.field("signed by", Line::text(&report.identity.subject));
    if let Some(id) = &report.identity.telematik_id {
        doc.field("Telematik-ID", Line::code(id));
    }
    doc.field("header", Line::code(report.header.to_string()));
    doc.field("jws", Line::code(&report.jws));
    out.render(&doc)?;
    Ok(Exit::Ok)
}

/// The claims: a JSON object from the file, or stdin for `-`.
fn read_claims(path: &std::path::Path) -> Result<Value, CliError> {
    let source = input::read(path)?;
    let value: Value = serde_json::from_slice(&source.bytes)
        .map_err(|error| CliError::Claims(format!("{}: {error}", source.name)))?;
    if !value.is_object() {
        return Err(CliError::Claims(format!(
            "{}: a JSON object is expected, not {}",
            source.name,
            kind_of(&value)
        )));
    }
    Ok(value)
}

fn kind_of(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "a boolean",
        Value::Number(_) => "a number",
        Value::String(_) => "a string",
        Value::Array(_) => "an array",
        Value::Object(_) => "an object",
    }
}

/// `typ` and the `--header NAME=VALUE` parameters; `alg` and `x5c` come from the
/// identity.
fn header_params(args: &IdentitySignArgs) -> Result<HeaderParams, CliError> {
    let mut params = HeaderParams::new().typ(&args.typ);
    for header in &args.header {
        let (name, raw) = header
            .split_once('=')
            .ok_or_else(|| CliError::Header(format!("{header:?} is not NAME=VALUE")))?;
        if name == "x5c" {
            return Err(CliError::Header("x5c is the identity's certificate".into()));
        }
        let value = serde_json::from_str(raw).unwrap_or_else(|_| Value::String(raw.to_owned()));
        params = params
            .param(name, value)
            .map_err(|error| CliError::Header(format!("{name}: {error}")))?;
    }
    Ok(params)
}

/// The decoded protected header of a compact JWS.
fn protected_header(jws: &str) -> Result<Value, CliError> {
    let encoded = jws.split('.').next().unwrap_or_default();
    let bytes = Base64UrlUnpadded::decode_vec(encoded)
        .map_err(|error| CliError::Signing(format!("header encoding: {error}")))?;
    serde_json::from_slice(&bytes).map_err(|error| CliError::Signing(format!("header: {error}")))
}
