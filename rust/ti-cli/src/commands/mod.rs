//! One module per command. A command builds a serde report, which is the JSON contract,
//! and renders the same report as text, so the two views cannot disagree.

mod agent;
mod cache;
mod connector;
mod documents;
mod inspect;
mod pkcs12;
mod probe;
mod profiles;
mod roots;
mod schema;
mod tsl;
mod verify;
mod version;

use ti_pki::{Certificate, Env, Timestamp};

use crate::cli::{
    CacheCommand, Cli, Command, Environment, Pkcs12Command, PkiCommand, ProfilesCommand,
    RootsCommand, TslCommand,
};
use crate::error::{CliError, Exit};
use crate::output::document::{date, when};
use crate::output::{Line, Output, Tone};
use crate::paths;
use crate::trust::TrustInfo;

/// Runs the parsed command line.
pub fn run(cli: &Cli, out: &Output) -> Result<Exit, CliError> {
    match paths::cache_dir(cli.global.cache_dir.as_deref()) {
        Ok(dir) => out.verbose(1, format_args!("cache {}", dir.display())),
        Err(error) => out.verbose(1, error),
    }
    out.verbose(1, &cli.global.net);
    match &cli.command {
        Command::Pki(PkiCommand::Inspect { file, p12_password }) => {
            inspect::run(file, p12_password, out)
        }
        Command::Pki(PkiCommand::Verify(args)) => verify::run(args, &cli.global, out),
        Command::Pki(PkiCommand::Profiles(ProfilesCommand::List)) => profiles::list(out),
        Command::Pki(PkiCommand::Profiles(ProfilesCommand::Describe { name })) => {
            profiles::describe(name, out)
        }
        Command::Pki(PkiCommand::Roots(RootsCommand::List(args))) => {
            roots::list(args, &cli.global, out)
        }
        Command::Pki(PkiCommand::Tsl(TslCommand::Show(args))) => tsl::show(args, &cli.global, out),
        Command::Pki(PkiCommand::Pkcs12(Pkcs12Command::Convert {
            input,
            output,
            p12_password,
            force,
        })) => pkcs12::convert(input, output, p12_password, *force, out),
        Command::Connector(connector) => connector::run(connector, &cli.global, out),
        Command::Probe { env } => probe::run(env.env, env.def, &cli.global, out),
        Command::Cache(CacheCommand::Clear) => cache::clear(&cli.global, out),
        Command::Schema { command } => schema::run(command, out),
        Command::Agent => agent::run(),
        Command::Version => version::run(out),
        Command::Completions { shell } => {
            let mut stdout = std::io::stdout().lock();
            clap_complete::generate(*shell, &mut crate::command(), crate::BIN, &mut stdout);
            Ok(Exit::Ok)
        }
    }
}

/// The environment of a command about one environment's trust material; auto has
/// nothing to detect from there.
fn concrete(env: Environment) -> Result<Env, CliError> {
    env.concrete().ok_or_else(|| {
        CliError::EnvironmentUndetected(
            "auto needs certificates to look at; this command shows one environment".into(),
        )
    })
}

/// `valid`, `expired` or `not_yet_valid` at `now`.
fn validity(cert: &Certificate, now: Timestamp) -> &'static str {
    if now < cert.not_before() {
        "not_yet_valid"
    } else if now > cert.not_after() {
        "expired"
    } else {
        "valid"
    }
}

/// ` · until 2029-11-06`, or ` · expired 2022-10-25` / ` · not yet valid` in red: the
/// expiry part of a list entry.
fn expiry(not_after: Timestamp, validity: &str) -> Line {
    match validity {
        "valid" => Line::dim(format!(" · until {}", date(not_after))),
        "expired" => Line::dim(" · ").and_status(Tone::Bad, format!("expired {}", date(not_after))),
        _ => Line::dim(" · ").and_status(Tone::Bad, "not yet valid"),
    }
}

/// The `O=` of a distinguished name.
fn organization(name: &str) -> Option<String> {
    inspect::dn_parts(name)
        .into_iter()
        .find_map(|part| part.strip_prefix("O=").map(str::to_owned))
}

/// `until 2029-11-06`, or `expired 2022-10-25` / `not yet valid` in red: the validity
/// cell of a table.
fn validity_cell(not_after: Timestamp, validity: &str) -> Line {
    match validity {
        "valid" => Line::text(format!("until {}", date(not_after))),
        "expired" => Line::status(Tone::Bad, format!("expired {}", date(not_after))),
        _ => Line::status(Tone::Bad, "not yet valid"),
    }
}

/// Counts, source, age and gaps of the trust material, for the `trust` field.
fn trust_line(trust: &TrustInfo) -> Line {
    let counts = format!("{} roots, {} TSL CAs", trust.roots, trust.intermediates);
    let mut line = if trust.note.is_some() {
        Line::status(Tone::Warn, counts)
    } else {
        Line::text(counts)
    };
    line = match trust.fetched_at_ts {
        Some(at) => line.and_dim(format!(" · {} {}", trust.source, when(at))),
        None => line.and_dim(format!(" · {}", trust.source)),
    };
    if let Some(next) = trust.tsl_next_update_ts {
        line = line.and_dim(format!(" · TSL next update {}", when(next)));
    }
    if let Some(note) = &trust.note {
        line = line.and_dim(format!(" · {note}"));
    }
    line
}

/// Writes `bytes` to `path`; readable by the owner only when `private` (keys, decrypted
/// documents). Never replaces an existing file unless `force`.
fn write_file(
    path: &std::path::Path,
    bytes: &[u8],
    force: bool,
    private: bool,
) -> Result<(), CliError> {
    use std::io::Write as _;
    let mut options = std::fs::OpenOptions::new();
    options.write(true);
    if force {
        options.create(true).truncate(true);
    } else {
        options.create_new(true);
    }
    #[cfg(unix)]
    if private {
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    }
    #[cfg(not(unix))]
    let _ = private;
    let mut file = options.open(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::AlreadyExists {
            CliError::OutputExists(path.display().to_string())
        } else {
            CliError::Output(std::io::Error::new(
                error.kind(),
                format!("{}: {error}", path.display()),
            ))
        }
    })?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}
