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

//! The `ti` command-line tool as a library: [`run`] parses the arguments, runs the
//! command and returns the exit code, so tests can drive it without a process.
//!
//! Conventions every command follows: results on stdout, diagnostics and errors on
//! stderr; `--format json` gives one JSON document with a `"schema"` version; colors
//! only on a terminal; never a prompt; exit codes as listed in `ti --help`.

mod block;
mod cli;
mod commands;
mod connector;
mod error;
mod http;
mod identity;
mod input;
mod net;
mod output;
mod paths;
mod peer;
mod store;
mod trust;

use std::ffi::OsString;
use std::process::ExitCode;

use clap::{CommandFactory, FromArgMatches};

pub use error::Exit;

/// The executable's name: everything the user sees (help, user agent, diagnostics, the
/// agent guide) takes it from here; it must match the `[[bin]]` name in Cargo.toml.
pub const BIN: &str = "ti";

use cli::Cli;
use output::Output;

/// The command line as clap sees it, named [`BIN`].
fn command() -> clap::Command {
    Cli::command()
        .name(BIN)
        .bin_name(BIN)
        .after_long_help(cli::AFTER_HELP.replace("{bin}", BIN))
}

/// Whether the command's `--env` took its value from `TI_ENV`.
fn env_from_variable(matches: &clap::ArgMatches) -> bool {
    let mut command = matches;
    while let Some((_, sub)) = command.subcommand() {
        command = sub;
    }
    command.ids().any(|id| id == "env")
        && command.value_source("env") == Some(clap::parser::ValueSource::EnvVariable)
}

/// Runs the tool with `args` (the program name first, as `std::env::args_os` yields
/// them).
pub fn run<I, T>(args: I) -> ExitCode
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let parsed = command().try_get_matches_from(args).and_then(|matches| {
        let mut cli = Cli::from_arg_matches(&matches)?;
        cli.global.env_from_variable = env_from_variable(&matches);
        Ok(cli)
    });
    let cli = match parsed {
        Ok(cli) => cli,
        Err(error) => {
            // clap prints help to stdout (exit 0) and errors to stderr (exit 2).
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
