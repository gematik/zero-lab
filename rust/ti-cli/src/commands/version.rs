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
