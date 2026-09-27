//! `ti pki pkcs12 convert|encode`: PKCS#12 files re-encoded the way every current reader
//! accepts them (DER, PBES2 AES-256, SHA-256 MAC), for use as a file or as the
//! credentials of a Konnektor configuration. `ti pki inspect` shows what a file holds.

use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::Path;

use base64ct::{Base64, Encoding};
use serde::Serialize;
use ti_pkcs12::{Pkcs12, Target};

use crate::error::{CliError, Exit};
use crate::input;
use crate::output::{Document, Line, Output, SCHEMA, warning};

/// `ti pki pkcs12 convert` as JSON.
#[derive(Serialize)]
struct ConvertReport {
    schema: u32,
    input: String,
    output: String,
    before: Protection,
    after: Protection,
    certificates: usize,
    keys: usize,
}

/// How a file is encoded and protected.
#[derive(Serialize)]
struct Protection {
    /// `DER` or `BER`.
    encoding: &'static str,
    /// E.g. `SHA-256 × 2048`; absent without a MAC.
    mac: Option<String>,
    /// Distinct algorithms, e.g. `certificates: PBES2 AES-256-CBC`.
    encryption: Vec<String>,
}

/// The credentials object of a `.kon` file, exactly as Konnektor clients read it.
#[derive(Serialize)]
struct Credentials<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    data: String,
    password: &'a str,
}

/// Runs `ti pki pkcs12 convert`.
pub fn convert(
    input_path: &Path,
    output_path: &Path,
    password: &str,
    force: bool,
    out: &Output,
) -> Result<Exit, CliError> {
    let source = input::read(input_path)?;
    let p12 = decode(&source, password)?;
    let converted = reencode(&p12, password, &source.name)?;
    write_private(output_path, &converted, force)?;
    let after = ti_pkcs12::decode(&converted, password).map_err(|error| CliError::Pkcs12 {
        source_name: output_path.display().to_string(),
        source: error,
    })?;
    let report = ConvertReport {
        schema: SCHEMA,
        input: source.name,
        output: output_path.display().to_string(),
        before: protection(&source.bytes, &p12),
        after: protection(&converted, &after),
        certificates: after.certificates.len(),
        keys: after.keys.len(),
    };
    if out.is_json() {
        out.json(&report)?;
    } else {
        let mut doc = Document::default();
        doc.field(
            "converted",
            Line::code(&report.input)
                .and_text(" → ")
                .and_code(&report.output),
        );
        doc.field("before", protection_line(&report.before));
        doc.field("after", protection_line(&report.after));
        doc.field(
            "content",
            format!(
                "{} certificate{}, {} key{}",
                report.certificates,
                plural(report.certificates),
                report.keys,
                plural(report.keys)
            ),
        );
        out.render(&doc)?;
    }
    Ok(Exit::Ok)
}

/// Runs `ti pki pkcs12 encode`: always the credentials JSON, whatever `--format` says,
/// since it is meant to be pasted into a `.kon` file.
pub fn encode(path: &Path, password: &str, out: &Output) -> Result<Exit, CliError> {
    let source = input::read(path)?;
    let p12 = decode(&source, password)?;
    let data = if needs_conversion(&source.bytes, &p12) {
        warning(format_args!(
            "{} is BER or uses legacy encryption; re-encoded (PBES2 AES-256, SHA-256 MAC) \
             so every Konnektor client reads it",
            source.name
        ));
        reencode(&p12, password, &source.name)?
    } else {
        source.bytes
    };
    out.json(&Credentials {
        kind: "pkcs12",
        data: Base64::encode_string(&data),
        password,
    })?;
    Ok(Exit::Ok)
}

fn decode(source: &input::Source, password: &str) -> Result<Pkcs12, CliError> {
    ti_pkcs12::decode(&source.bytes, password).map_err(|error| CliError::Pkcs12 {
        source_name: source.name.clone(),
        source: error,
    })
}

/// BER, or encryption that OpenSSL 3 reads only with `-legacy` and the Go decoder not
/// at all (RC2).
fn needs_conversion(bytes: &[u8], p12: &Pkcs12) -> bool {
    is_ber(bytes)
        || p12
            .encryption
            .iter()
            .any(|e| e.algorithm.starts_with("PKCS#12"))
}

fn is_ber(bytes: &[u8]) -> bool {
    bytes.get(1) == Some(&0x80)
}

fn reencode(p12: &Pkcs12, password: &str, name: &str) -> Result<Vec<u8>, CliError> {
    // Salt and IV for each key and the certificate safe, and the MAC salt.
    let mut pool = vec![0u8; 32 * (p12.keys.len() + 1) + 8];
    rustls::crypto::ring::default_provider()
        .secure_random
        .fill(&mut pool)
        .map_err(|_| CliError::Output(io::Error::other("no system randomness")))?;
    let mut offset = 0;
    ti_pkcs12::encode(p12, password, |buf: &mut [u8]| {
        buf.copy_from_slice(&pool[offset..offset + buf.len()]);
        offset += buf.len();
    })
    .map_err(|error| CliError::Pkcs12 {
        source_name: name.to_owned(),
        source: error,
    })
}

/// Writes `bytes` to `path` readable by the owner only, as keys deserve; refuses to
/// replace an existing file unless `force`.
fn write_private(path: &Path, bytes: &[u8], force: bool) -> Result<(), CliError> {
    let mut options = OpenOptions::new();
    options.write(true);
    if force {
        options.create(true).truncate(true);
    } else {
        options.create_new(true);
    }
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options.open(path).map_err(|error| {
        if error.kind() == io::ErrorKind::AlreadyExists {
            CliError::OutputExists(path.display().to_string())
        } else {
            CliError::Output(io::Error::new(
                error.kind(),
                format!("{}: {error}", path.display()),
            ))
        }
    })?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn protection(bytes: &[u8], p12: &Pkcs12) -> Protection {
    let mut encryption: Vec<String> = Vec::new();
    for e in &p12.encryption {
        let target = if e.target == Target::Key {
            "key"
        } else {
            "certificates"
        };
        let entry = format!("{target}: {}", e.algorithm);
        if !encryption.contains(&entry) {
            encryption.push(entry);
        }
    }
    Protection {
        encoding: if is_ber(bytes) { "BER" } else { "DER" },
        mac: p12
            .mac
            .as_ref()
            .map(|mac| format!("{} × {}", mac.digest, mac.iterations)),
        encryption,
    }
}

fn protection_line(p: &Protection) -> Line {
    let mut line = Line::text(p.encoding);
    line = line.and_dim(format!(" · MAC {}", p.mac.as_deref().unwrap_or("none")));
    for e in &p.encryption {
        line = line.and_dim(format!(" · {e}"));
    }
    line
}

fn plural(n: usize) -> &'static str {
    if n == 1 { "" } else { "s" }
}
