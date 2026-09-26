//! `tir`: the command-line tool for the gematik Telematikinfrastruktur, in Rust.

use std::process::ExitCode;

fn main() -> ExitCode {
    ti_cli::run(std::env::args_os())
}
