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

//! `ti pki pkcs12 convert`: PKCS#12 files re-encoded the way every current reader
//! accepts them (DER, PBES2 AES-256, SHA-256 MAC). `ti pki inspect` shows what a file
//! holds.

use std::path::Path;

use serde::Serialize;
use ti_client::pkcs12::{self as engine, Protection};

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

/// Runs `ti pki pkcs12 convert`.
pub fn convert(
    input_path: &Path,
    output_path: &Path,
    password: &str,
    force: bool,
    out: &Output,
) -> Result<Exit, CliError> {
    let source = input::read(input_path)?;
    let converted = engine::convert(&source.bytes, &source.name, password)?;
    super::write_file(output_path, &converted.bytes, force, true)?;
    let after = engine::content(
        &converted.bytes,
        &output_path.display().to_string(),
        password,
    )?;
    let report = ConvertReport {
        schema: SCHEMA,
        input: source.name,
        output: output_path.display().to_string(),
        before: converted.before,
        after: after.protection,
        certificates: after.certificates,
        keys: after.keys,
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
