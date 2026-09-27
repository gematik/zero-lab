//! Everything written to stdout and stderr. Results go to stdout, diagnostics and errors
//! to stderr; styles are stripped automatically where they do not belong.

pub mod document;
mod json;
mod markdown;
pub mod style;
mod text;
mod waiting;

use core::fmt::Display;
use std::io::{self, IsTerminal, StdoutLock, Write};

use anstream::AutoStream;
use serde::Serialize;
use x509_cert::der::oid::ObjectIdentifier;

use crate::cli::{Format, GlobalArgs};
use crate::error::CliError;
pub use document::{Document, Line, Tone};
pub use waiting::Waiting;

/// The JSON contract version every document carries as `"schema"`.
pub const SCHEMA: u32 = 1;

/// How this invocation writes its results.
pub struct Output {
    format: Format,
    /// Pretty, highlighted JSON on a terminal; compact when piped.
    pretty: bool,
    verbose: u8,
}

impl Output {
    /// From the global options and whether stdout is a terminal.
    pub fn new(global: &GlobalArgs) -> Self {
        let terminal = io::stdout().is_terminal();
        Output {
            format: match global.format {
                Format::Auto if terminal => Format::Text,
                Format::Auto => Format::Markdown,
                chosen => chosen,
            },
            pretty: terminal,
            verbose: global.verbose,
        }
    }

    /// Writes `doc` on stdout as text or Markdown, per `--format`.
    pub fn render(&self, doc: &Document) -> Result<(), CliError> {
        if self.format == Format::Markdown {
            markdown::render(doc, &mut io::stdout().lock())?;
        } else {
            text::render(doc, &mut stdout())?;
        }
        Ok(())
    }

    /// Writes a report that reads differently on a terminal and in Markdown: `text`
    /// with sections for the terminal, `markdown` compact for notes and chats.
    pub fn render_views(&self, text: &Document, markdown: &Document) -> Result<(), CliError> {
        if self.format == Format::Markdown {
            markdown::render(markdown, &mut io::stdout().lock())?;
        } else {
            text::render(text, &mut stdout())?;
        }
        Ok(())
    }

    /// Whether results are JSON.
    pub fn is_json(&self) -> bool {
        self.format == Format::Json
    }

    /// Writes `report` as one JSON document on stdout.
    pub fn json<T: Serialize>(&self, report: &T) -> Result<(), CliError> {
        let mut out = stdout();
        if self.pretty {
            json::write_highlighted(&mut out, &serde_json::to_string_pretty(report)?)?;
        } else {
            serde_json::to_writer(&mut out, report)?;
        }
        writeln!(out)?;
        out.flush()?;
        Ok(())
    }

    /// A diagnostic on stderr, shown from verbosity `level` on.
    pub fn verbose(&self, level: u8, message: impl Display) {
        if self.verbose >= level {
            diagnostic(message);
        }
    }

    /// The `-v` count, for components that log on their own.
    pub fn verbosity(&self) -> u8 {
        self.verbose
    }

    /// Reports `error` on stderr: text with a hint, or a JSON document.
    pub fn error(&self, error: &CliError) {
        let mut err = anstream::stderr();
        // Nothing sensible is left to do if stderr itself fails.
        let _ = if self.is_json() {
            let document = serde_json::json!({
                "schema": SCHEMA,
                "error": {
                    "kind": error.kind(),
                    "message": error.to_string(),
                    "hint": error.hint(),
                }
            });
            writeln!(err, "{document}")
        } else {
            let (bad, dim) = (style::BAD, style::DIM);
            writeln!(err, "{bad}error:{bad:#} {error}").and_then(|()| match error.hint() {
                Some(hint) => writeln!(err, "{dim}  hint: {hint}{dim:#}"),
                None => Ok(()),
            })
        };
    }
}

/// A diagnostic line on stderr, dimmed.
pub fn diagnostic(message: impl Display) {
    let dim = style::DIM;
    // Starts on a clean line where a waiting spinner may be drawing.
    if io::stderr().is_terminal() {
        let _ = write!(io::stderr(), "\r\x1b[2K");
    }
    // A diagnostic that cannot be written is not worth failing the command.
    let _ = writeln!(anstream::stderr(), "{dim}{}: {message}{dim:#}", crate::BIN);
}

/// A warning on stderr, whatever the verbosity: something the user should not miss.
pub fn warning(message: impl Display) {
    let warn = style::WARN;
    let _ = writeln!(anstream::stderr(), "{warn}warning:{warn:#} {message}");
}

/// Stdout for text output; styles are stripped where they do not belong.
pub fn stdout() -> AutoStream<StdoutLock<'static>> {
    anstream::stdout().lock()
}

/// `der` as a PEM `CERTIFICATE` block, LF line endings.
pub fn pem(der: &[u8]) -> String {
    pem_rfc7468::encode_string("CERTIFICATE", pem_rfc7468::LineEnding::LF, der)
        .expect("base64 of a certificate held in memory cannot fail")
}

/// An OID with its gemSpec_OID description, where the TI defines one.
#[derive(Serialize)]
pub struct OidInfo {
    /// Dotted form.
    pub oid: String,
    /// The description from gemSpec_OID.
    pub name: Option<&'static str>,
}

impl OidInfo {
    /// Looks `oid` up in the gemSpec_OID tables.
    pub fn new(oid: &ObjectIdentifier) -> Self {
        OidInfo {
            oid: oid.to_string(),
            name: ti_pki::oid::lookup(oid)
                .map(|info| info.description)
                .filter(|d| !d.is_empty()),
        }
    }
}

impl Display for OidInfo {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let (id, dim) = (style::ID, style::DIM);
        write!(f, "{id}{}{id:#}", self.oid)?;
        match self.name {
            Some(name) => write!(f, "  {dim}{name}{dim:#}"),
            None => Ok(()),
        }
    }
}

/// `bytes` as upper-case hex pairs separated by `:`, as OpenSSL prints fingerprints.
pub fn hex(bytes: &[u8]) -> String {
    let pairs: Vec<String> = bytes.iter().map(|b| format!("{b:02X}")).collect();
    pairs.join(":")
}
