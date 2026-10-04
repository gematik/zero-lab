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
    CacheCommand, Cli, Command, Environment, GlobalArgs, Pkcs12Command, PkiCommand, ProbeEnv,
    ProfilesCommand, RootsCommand, TslCommand,
};
use crate::error::{CliError, Exit};
use crate::output::document::{TreeRow, date, when};
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
            inspect::run(file, p12_password, &cli.global, out)
        }
        Command::Pki(PkiCommand::Verify(args)) => verify::run(args, &cli.global, out),
        Command::Pki(PkiCommand::Profiles(ProfilesCommand::List)) => profiles::list(out),
        Command::Pki(PkiCommand::Profiles(ProfilesCommand::Describe { name, env, offline })) => {
            profiles::describe(name, *env, *offline, &cli.global, out)
        }
        Command::Pki(PkiCommand::Roots(RootsCommand::List(args))) => {
            roots::list(args, &cli.global, out)
        }
        Command::Pki(PkiCommand::Tsl(TslCommand::Show(args))) => tsl::show(args, &cli.global, out),
        Command::Pki(PkiCommand::Tsl(TslCommand::Verify(args))) => {
            tsl::verify(args, &cli.global, out)
        }
        Command::Pki(PkiCommand::Pkcs12(Pkcs12Command::Convert {
            input,
            output,
            p12_password,
            force,
        })) => pkcs12::convert(input, output, p12_password, *force, out),
        Command::Connector(connector) => connector::run(connector, &cli.global, out),
        Command::Probe { target, env } => {
            let (env, def) = probe_target(*target, *env, &cli.global)?;
            probe::run(env, def, &cli.global, out)
        }
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

/// The environment of a command about one environment's trust material. There is
/// nothing to detect from, so `auto` from `TI_ENV` is the default, production; an `auto`
/// on the command line is an error.
fn concrete(env: Environment, global: &GlobalArgs) -> Result<Env, CliError> {
    match env.concrete() {
        Some(env) => Ok(env),
        None if global.env_from_variable => Ok(Env::Prod),
        None => Err(CliError::Environment(
            "--env auto needs certificates to look at; this command shows one environment".into(),
        )),
    }
}

/// The environment `probe` checks: ENV, else `--env`, else `TI_ENV`. ENV and an `--env`
/// on the command line must agree; ENV wins over `TI_ENV`, and `auto` from `TI_ENV`
/// counts as unset.
fn probe_target(
    target: Option<ProbeEnv>,
    option: Option<Environment>,
    global: &GlobalArgs,
) -> Result<(Env, bool), CliError> {
    let option = match option {
        Some(Environment::Auto) if global.env_from_variable => None,
        Some(env) => Some(env.concrete().ok_or_else(|| {
            CliError::Environment("probe checks one environment; auto has nothing to detect".into())
        })?),
        None => None,
    };
    match (target, option) {
        (Some(target), Some(env)) if !global.env_from_variable && target.env != env => {
            Err(CliError::Environment(format!(
                "ENV {} and --env {} disagree",
                target.env.as_str(),
                env.as_str()
            )))
        }
        (Some(target), _) => Ok((target.env, target.def)),
        (None, Some(env)) => Ok((env, false)),
        (None, None) => Err(CliError::Environment(
            "probe needs an environment: ENV, --env or TI_ENV".into(),
        )),
    }
}

/// `valid`, `expired` or `not_yet_valid` at `now`.
fn validity(cert: &Certificate, now: Timestamp) -> &'static str {
    ti_report::validity(cert, now)
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

/// A chain as rows of a tree, the first certificate at the top and the root at the
/// bottom: each with `mark(i)` before its common name, then its place in the chain and
/// validity at `at`, then `extra(i)`. An incomplete chain ends with the issuer that was
/// not found.
fn chain_tree(
    chain: &[Certificate],
    complete: bool,
    at: Timestamp,
    mark: impl Fn(usize) -> Line,
    extra: impl Fn(usize) -> Line,
) -> Vec<TreeRow> {
    let last = chain.len().saturating_sub(1);
    let mut rows: Vec<TreeRow> = chain
        .iter()
        .enumerate()
        .map(|(i, cert)| {
            let place = match i {
                i if i == last && complete && i > 0 => "root",
                0 if cert.is_ca() && complete && chain.len() == 1 => "root",
                0 if !cert.is_ca() => "end entity",
                _ => "CA",
            };
            let name = if i == 0 {
                Line::strong(cert.subject_cn())
            } else {
                Line::text(cert.subject_cn())
            };
            TreeRow {
                name: mark(i).and_line(name),
                detail: Line::dim(place)
                    .and_line(expiry(cert.not_after(), validity(cert, at)))
                    .and_line(extra(i)),
            }
        })
        .collect();
    if !complete && let Some(last) = chain.last() {
        let issuer_name = last.issuer().to_string();
        let (issuer, _) = inspect::split_name(&issuer_name);
        rows.push(TreeRow {
            name: Line::status(Tone::Warn, "? ").and_text(issuer.unwrap_or("unnamed issuer")),
            detail: Line::status(Tone::Warn, "issuer not among the trusted CAs"),
        });
    }
    rows
}

/// The verified TSL as its own trust chain, for the Trust section: the list, its signer
/// and the TSL signer CA, valid at `at` since the list verified then.
fn tsl_tree(trust: &TrustInfo, at: Timestamp) -> Vec<TreeRow> {
    let Some(tsl) = &trust.tsl else {
        return Vec::new();
    };
    let ok = || Line::status(Tone::Good, "✓ ");
    let next_update = trust.tsl_next_update_ts.map_or_else(
        || " · closed list".to_owned(),
        |t| format!(" · next update {}", date(t)),
    );
    let ocsp = match tsl.signer_ocsp {
        Some(status) => Line::text(" · ").and_status(Tone::Good, format!("OCSP {status}")),
        None => Line::text(" · ").and_status(Tone::Warn, "OCSP not checked"),
    };
    let row = |cert: &Certificate, place: &str| {
        Line::dim(place.to_owned()).and_line(expiry(cert.not_after(), validity(cert, at)))
    };
    vec![
        TreeRow {
            name: ok().and_line(Line::strong(format!("TSL #{}", tsl.sequence_number))),
            detail: Line::dim(format!(
                "list{next_update} · {} CAs under the roots",
                trust.intermediates
            )),
        },
        TreeRow {
            name: ok().and_text(&tsl.signer.common_name),
            detail: row(&tsl.signer.certificate, "TSL signer").and_line(ocsp),
        },
        TreeRow {
            name: ok().and_text(&tsl.tsl_signer_ca.common_name),
            detail: row(&tsl.tsl_signer_ca.certificate, "TSL signer CA · embedded"),
        },
    ]
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
    for warning in &trust.tsl_warnings {
        line = line
            .and_dim(" · ")
            .and_status(Tone::Warn, format!("TSL {}", tsl_warning_text(warning)));
    }
    if let Some(note) = &trust.note {
        line = line.and_dim(format!(" · {note}"));
    }
    line
}

/// A TSL warning code in words.
fn tsl_warning_text(code: &str) -> &str {
    match code {
        "no_ocsp_check" => "signer status not checked",
        "validity_warning_1" => "past NextUpdate, in the grace period",
        "tsl_anchor_announced" => "announces a new TSL signer CA",
        other => other,
    }
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

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;
    use crate::cli::ProbeEnv;

    fn global(env_from_variable: bool) -> GlobalArgs {
        let mut global = Cli::try_parse_from(["ti", "version"]).unwrap().global;
        global.env_from_variable = env_from_variable;
        global
    }

    fn target(env: Env) -> ProbeEnv {
        ProbeEnv { env, def: false }
    }

    #[test]
    fn auto_from_ti_env_is_production_where_nothing_is_detected() {
        assert_eq!(
            concrete(Environment::Auto, &global(true)).unwrap(),
            Env::Prod
        );
        assert!(concrete(Environment::Auto, &global(false)).is_err());
        assert_eq!(concrete(Environment::Ref, &global(true)).unwrap(), Env::Ref);
    }

    #[test]
    fn probe_env_argument_wins_over_ti_env_only() {
        let from_variable = global(true);
        let on_command_line = global(false);
        assert_eq!(
            probe_target(
                Some(target(Env::Ref)),
                Some(Environment::Test),
                &from_variable
            )
            .unwrap(),
            (Env::Ref, false)
        );
        assert!(
            probe_target(
                Some(target(Env::Ref)),
                Some(Environment::Test),
                &on_command_line
            )
            .is_err()
        );
        assert_eq!(
            probe_target(
                Some(target(Env::Ref)),
                Some(Environment::Ref),
                &on_command_line
            )
            .unwrap(),
            (Env::Ref, false)
        );
        assert_eq!(
            probe_target(None, Some(Environment::Test), &from_variable).unwrap(),
            (Env::Test, false)
        );
        assert_eq!(
            probe_target(
                Some(target(Env::Dev)),
                Some(Environment::Auto),
                &from_variable
            )
            .unwrap(),
            (Env::Dev, false)
        );
        assert!(probe_target(None, Some(Environment::Auto), &from_variable).is_err());
        assert!(probe_target(None, None, &on_command_line).is_err());
    }
}
