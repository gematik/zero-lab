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

//! `ti version`: which build this is, for bug reports and for agents that check what
//! they are talking to.

use serde::Serialize;

use crate::error::{CliError, Exit};
use crate::output::{Document, Line, Output, SCHEMA};

/// The JSON document.
#[derive(Serialize)]
struct Report {
    schema: u32,
    /// The executable's name.
    name: &'static str,
    version: &'static str,
    /// `std::env::consts::OS`, e.g. `macos`, `linux`, `windows`.
    os: &'static str,
    /// `std::env::consts::ARCH`, e.g. `aarch64`, `x86_64`.
    arch: &'static str,
}

/// Runs `ti version`.
pub fn run(out: &Output) -> Result<Exit, CliError> {
    let report = Report {
        schema: SCHEMA,
        name: crate::BIN,
        version: env!("CARGO_PKG_VERSION"),
        os: std::env::consts::OS,
        arch: std::env::consts::ARCH,
    };
    if out.is_json() {
        out.json(&report)?;
    } else {
        let mut doc = Document::default();
        doc.paragraph(
            Line::strong(format!("{} {}", report.name, report.version))
                .and_dim(format!(" · {} {}", report.os, report.arch)),
        );
        out.render(&doc)?;
    }
    Ok(Exit::Ok)
}
