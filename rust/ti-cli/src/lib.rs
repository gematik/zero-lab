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
//! only on a terminal; exit codes as listed in `ti --help`. A prompt only on a terminal
//! (stdin and stderr), in commands meant for people (`connector config new`, `edit`,
//! `pin`), each of them fully usable through its options; without a terminal a missing
//! option is an error, never a wait.

mod block;
mod cli;
mod commands;
mod connector;
mod error;
// Public for the fuzz targets only; not an API of this crate.
#[doc(hidden)]
pub mod files;
mod http;
mod identity;
mod input;
mod net;
mod output;
mod paths;
mod peer;
// Public for the fuzz targets only; not an API of this crate.
#[doc(hidden)]
pub mod profile;
mod prompt;
// Public for the spec/store interoperability driver (examples/store-interop.rs) only;
// not an API of this crate.
#[doc(hidden)]
pub mod store;
mod trust;

use std::ffi::OsString;
use std::io::Write as _;
use std::process::ExitCode;

use clap::{CommandFactory, FromArgMatches};

pub use error::Exit;

/// The current time in whole seconds.
pub(crate) fn now() -> ti_types::Timestamp {
    ti_types::Timestamp(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()),
    )
}

/// The executable's name: everything the user sees (help, user agent, diagnostics, the
/// agent guide) takes it from here; it must match the `[[bin]]` name in Cargo.toml.
pub const BIN: &str = "ti";

use cli::Cli;
use output::Output;

/// The command line as clap sees it, named [`BIN`].
fn command() -> clap::Command {
    with_more_options_hint(Cli::command())
        .name(BIN)
        .bin_name(BIN)
        .after_long_help(cli::AFTER_HELP.replace("{bin}", BIN))
}

/// The short help, shown when a command group is called without its subcommand, leaves
/// out the options every command shares, so that the commands stand out, and says
/// where the others are; `-h` and `--help` both show everything.
fn with_more_options_hint(command: clap::Command) -> clap::Command {
    command
        .after_help("The options every command shares: --help")
        .after_long_help("")
        .disable_help_flag(true)
        // The derived arguments leave the heading at "HTTP options".
        .next_help_heading(None::<&str>)
        .arg(
            clap::Arg::new("help")
                .short('h')
                .long("help")
                .action(clap::ArgAction::HelpLong)
                .help("Print help"),
        )
        .mut_subcommands(with_more_options_hint)
}

/// The short help of the deepest command `args` name.
fn short_help(args: &[OsString]) -> clap::builder::StyledStr {
    let mut command = command();
    command.build();
    let mut command = &mut command;
    for arg in args.iter().skip(1) {
        let Some(name) = arg.to_str() else { continue };
        if command.find_subcommand(name).is_none() {
            continue;
        }
        command = command
            .find_subcommand_mut(name)
            .expect("found just before");
    }
    command.render_help()
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
    let args: Vec<OsString> = args.into_iter().map(Into::into).collect();
    let parsed = command().try_get_matches_from(&args).and_then(|matches| {
        let mut cli = Cli::from_arg_matches(&matches)?;
        cli.global.env_from_variable = env_from_variable(&matches);
        Ok(cli)
    });
    let cli = match parsed {
        Ok(cli) => cli,
        Err(error) if error.kind() == clap::error::ErrorKind::MissingSubcommand => {
            // clap shows the help only when no argument at all is present, and a set
            // TI_FORMAT or TI_CACHE_DIR counts as one; show it in that case too.
            let _ = writeln!(std::io::stderr(), "{}", short_help(&args));
            return Exit::Usage.into();
        }
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
