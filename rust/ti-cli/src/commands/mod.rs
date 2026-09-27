//! One module per command. A command builds a serde report, which is the JSON contract,
//! and renders the same report as text, so the two views cannot disagree.

mod inspect;
mod profiles;
mod verify;

use crate::cli::{Cli, Command, PkiCommand, ProfilesCommand};
use crate::error::{CliError, Exit};
use crate::output::Output;
use crate::paths;

/// Runs the parsed command line.
pub fn run(cli: &Cli, out: &Output) -> Result<Exit, CliError> {
    match paths::cache_dir(cli.global.cache_dir.as_deref()) {
        Ok(dir) => out.verbose(1, format_args!("cache {}", dir.display())),
        Err(error) => out.verbose(1, error),
    }
    out.verbose(1, &cli.global.net);
    match &cli.command {
        Command::Pki(PkiCommand::Inspect { file }) => inspect::run(file, out),
        Command::Pki(PkiCommand::Verify(args)) => verify::run(args, &cli.global, out),
        Command::Pki(PkiCommand::Profiles(ProfilesCommand::List)) => profiles::list(out),
        Command::Pki(PkiCommand::Profiles(ProfilesCommand::Describe { name })) => {
            profiles::describe(name, out)
        }
    }
}
