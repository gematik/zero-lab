//! `ti pki pkcs12 convert`: PKCS#12 files re-encoded the way every current reader
//! accepts them (DER, PBES2 AES-256, SHA-256 MAC). `ti pki inspect` shows what a file
//! holds.

use std::io;
use std::path::Path;

use serde::Serialize;
use ti_pkcs12::{Pkcs12, Target};

use crate::error::{CliError, Exit};
use crate::input;
use crate::output::{Document, Line, Output, SCHEMA};

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
    let converted = encode(&p12, password, &source.name)?;
    super::write_file(output_path, &converted, force, true)?;
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

fn decode(source: &input::Source, password: &str) -> Result<Pkcs12, CliError> {
    ti_pkcs12::decode(&source.bytes, password).map_err(|error| CliError::Pkcs12 {
        source_name: source.name.clone(),
        source: error,
    })
}

fn is_ber(bytes: &[u8]) -> bool {
    bytes.get(1) == Some(&0x80)
}

/// `p12` encoded with `password`, salts and IVs from the system's randomness; `name`
/// names it in errors.
pub(super) fn encode(p12: &Pkcs12, password: &str, name: &str) -> Result<Vec<u8>, CliError> {
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
