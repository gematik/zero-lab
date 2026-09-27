//! `ti agent`: the usage guide for scripts and AI agents, compiled in so it matches
//! the binary and works offline.

use std::io::Write;

use crate::error::{CliError, Exit};

const GUIDE: &str = include_str!("../../AGENTS.md");

/// Prints the guide, `{bin}` replaced by the executable's name; Markdown whatever
/// `--format` says.
pub fn run() -> Result<Exit, CliError> {
    let mut out = std::io::stdout().lock();
    out.write_all(GUIDE.replace("{bin}", crate::BIN).as_bytes())?;
    out.flush()?;
    Ok(Exit::Ok)
}
