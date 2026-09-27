//! The command line: global options, HTTP options and the command tree.

use std::path::PathBuf;

use clap::builder::PossibleValuesParser;
use clap::{ArgAction, Args, Parser, Subcommand, ValueEnum};

use crate::net::NetArgs;

const AFTER_HELP: &str = "\
Exit codes:
  0  success; for verify: the certificate is valid
  1  the certificate is not valid
  2  wrong arguments or options
  3  trust material (roots.json, TSL) unavailable
  4  input unreadable or without a certificate
  5  output could not be written

Environment:
  TI_FORMAT       default for --format (auto, text, markdown, json)
  TI_ENV          default for verify --env (auto, prod, ref, test, dev)
  TI_CACHE_DIR    default for --cache-dir
  NO_COLOR        disables colors; CLICOLOR_FORCE=1 forces them

Examples:
  tir pki inspect card.pem
  tir pki inspect - < card.pem
  tir pki inspect card.pem > card.md          # Markdown, as piped output is
  tir --format json pki inspect card.pem | jq .certificates[0].certificate_type
  tir pki profiles describe smb-aut
  tir pki verify card.pem --issuer ca.pem
  tir pki verify card.pem --env ref --profile none --at 2026-06-01T00:00:00Z";

/// The gematik TI command-line tool (Rust).
///
/// Offline by default where possible; every command is non-interactive.
#[derive(Debug, Parser)]
#[command(
    name = "tir",
    version,
    propagate_version = true,
    after_long_help = AFTER_HELP,
    max_term_width = 100
)]
pub struct Cli {
    /// Options for every command.
    #[command(flatten)]
    pub global: GlobalArgs,
    /// What to do.
    #[command(subcommand)]
    pub command: Command,
}

/// Options for every command.
#[derive(Debug, Args)]
pub struct GlobalArgs {
    /// Output format: auto is text on a terminal and Markdown when piped
    #[arg(long, value_enum, default_value_t = Format::Auto, env = "TI_FORMAT", global = true)]
    pub format: Format,
    /// When to use colors; auto uses them on a terminal only
    #[arg(long, value_enum, default_value_t = ColorWhen::Auto, value_name = "WHEN", global = true)]
    pub color: ColorWhen,
    /// Diagnostics on stderr (-v, -vv)
    #[arg(short, long, action = ArgAction::Count, global = true)]
    pub verbose: u8,
    /// Cache directory [default: ~/.cache/telematik/ti, %LOCALAPPDATA%\telematik\ti on Windows]
    #[arg(long, value_name = "DIR", env = "TI_CACHE_DIR", global = true)]
    pub cache_dir: Option<PathBuf>,
    /// HTTP options.
    #[command(flatten)]
    pub net: NetArgs,
}

/// `--format`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum Format {
    /// Text on a terminal, Markdown when piped.
    Auto,
    /// Aligned text, colored on a terminal.
    Text,
    /// CommonMark with tables, for notes, chats and agents.
    Markdown,
    /// One document with a "schema" version, stable within it; pretty on a terminal.
    Json,
}

/// `--color`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum ColorWhen {
    /// On a terminal, unless NO_COLOR is set.
    Auto,
    /// Always, also when piped.
    Always,
    /// Never.
    Never,
}

impl From<ColorWhen> for anstream::ColorChoice {
    fn from(when: ColorWhen) -> Self {
        match when {
            ColorWhen::Auto => anstream::ColorChoice::Auto,
            ColorWhen::Always => anstream::ColorChoice::Always,
            ColorWhen::Never => anstream::ColorChoice::Never,
        }
    }
}

/// The command groups.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Certificates and PKI trust
    #[command(subcommand)]
    Pki(PkiCommand),
}

/// `tir pki …`.
#[derive(Debug, Subcommand)]
pub enum PkiCommand {
    /// Decode certificates and show what the TI reads from them (offline; does not validate)
    Inspect {
        /// PEM or DER file with one or more certificates; "-" reads stdin
        #[arg(value_name = "FILE")]
        file: PathBuf,
    },
    /// List the validation profiles or show what one requires
    #[command(subcommand)]
    Profiles(ProfilesCommand),
    /// Build the chain to the TI roots and validate it (exit 0 valid, 1 not valid)
    Verify(VerifyArgs),
}

/// `tir pki verify`.
#[derive(Debug, Args)]
pub struct VerifyArgs {
    /// PEM or DER file, the end entity first; further certificates are candidate
    /// intermediates; "-" reads stdin
    #[arg(value_name = "FILE")]
    pub file: PathBuf,
    /// TI environment; auto detects production or test from the certificates
    #[arg(long, value_enum, default_value_t = Environment::Auto, env = "TI_ENV")]
    pub env: Environment,
    /// Issuing CA certificate (PEM or DER), when the TSL does not provide it
    #[arg(long, value_name = "FILE")]
    pub issuer: Option<PathBuf>,
    /// Further candidate intermediates (PEM or DER); repeatable
    #[arg(long, value_name = "FILE")]
    pub intermediates: Vec<PathBuf>,
    /// Validation profile: auto picks it from the certificate, none checks the chain only
    #[arg(long, default_value = "auto", value_parser = profile_selectors())]
    pub profile: String,
    /// No network: cached trust material, else the embedded roots; revocation is not
    /// checked
    #[arg(long)]
    pub offline: bool,
    /// Validate at this time instead of now (RFC 3339, e.g. 2026-06-01T00:00:00+02:00)
    #[arg(long, value_name = "TIME", value_parser = timestamp)]
    pub at: Option<ti_pki::Timestamp>,
}

/// `--env`: an environment, or auto-detection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum Environment {
    /// Production if the certificates chain to production roots, else test/reference.
    Auto,
    /// Production.
    #[value(alias = "pu")]
    Prod,
    /// Reference environment.
    #[value(alias = "ru")]
    Ref,
    /// Test environment.
    #[value(alias = "tu")]
    Test,
    /// Development; shares the reference trust material.
    Dev,
}

fn profile_selectors() -> PossibleValuesParser {
    PossibleValuesParser::new(ti_pki::profile::selector_values())
}

fn timestamp(value: &str) -> Result<ti_pki::Timestamp, String> {
    ti_pki::Timestamp::parse_rfc3339(value).ok_or_else(|| {
        format!("{value:?} is not an RFC 3339 time with a zone, e.g. 2026-06-01T00:00:00Z")
    })
}

/// `tir pki profiles …`.
#[derive(Debug, Subcommand)]
pub enum ProfilesCommand {
    /// List the profiles
    List,
    /// Show what a profile requires of each certificate type it accepts
    Describe {
        /// Profile name
        #[arg(value_parser = profile_names())]
        name: String,
    },
}

fn profile_names() -> PossibleValuesParser {
    PossibleValuesParser::new(ti_pki::profile::PROFILES.iter().map(|p| p.name))
}
