//! The `tir` command-line tool as a library: [`run`] parses the arguments, runs the
//! command and returns the exit code, so tests can drive it without a process.
//!
//! Conventions every command follows: results on stdout, diagnostics and errors on
//! stderr; `--format json` gives one JSON document with a `"schema"` version; colors
//! only on a terminal; never a prompt; exit codes as listed in `tir --help`.

mod block;
mod cache;
mod cli;
mod commands;
mod error;
mod http;
mod input;
mod net;
mod output;
mod paths;
mod trust;

use std::ffi::OsString;
use std::process::ExitCode;

use clap::Parser;

pub use error::Exit;

use cli::Cli;
use output::Output;

/// Runs `tir` with `args` (the program name first, as `std::env::args_os` yields them).
pub fn run<I, T>(args: I) -> ExitCode
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let cli = match Cli::try_parse_from(args) {
        Ok(cli) => cli,
        Err(error) => {
            // clap prints help and version to stdout (exit 0) and errors to stderr (exit 2).
            let _ = error.print();
            return ExitCode::from(u8::try_from(error.exit_code()).unwrap_or(2));
        }
    };
    anstream::ColorChoice::write_global(cli.global.color.into());
    let out = Output::new(&cli.global);
    match commands::run(&cli, &out) {
        Ok(exit) => exit.into(),
        Err(error) if error.is_broken_pipe() => Exit::Ok.into(),
        Err(error) => {
            out.error(&error);
            error.exit().into()
        }
    }
}
