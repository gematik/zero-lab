//! The command line: global options, HTTP options and the command tree.

use std::path::PathBuf;

use clap::builder::PossibleValuesParser;
use clap::{ArgAction, Args, Parser, Subcommand, ValueEnum};

use crate::net::NetArgs;

/// Exit codes, variables and examples; `{bin}` stands for [`crate::BIN`].
pub const AFTER_HELP: &str = "\
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
  {bin} pki inspect card.pem
  {bin} pki inspect - < card.pem
  {bin} pki inspect card.pem > card.md          # Markdown, as piped output is
  {bin} --format json pki inspect card.pem | jq .certificates[0].certificate_type
  {bin} pki profiles describe smb-aut
  {bin} pki verify card.pem --issuer ca.pem
  {bin} pki verify card.pem --env ref --profile none --at 2026-06-01T00:00:00Z
  {bin} pki roots list --env ref
  {bin} pki tsl show --rejected
  {bin} pki tsl show --ca SMCB-CA51 --format markdown   # with the CA's PEM
  {bin} schema pki verify                       # the JSON contract of one command
  {bin} agent                                   # usage guide for scripts and agents
  {bin} version
  {bin} completions zsh > ~/.zfunc/_{bin}      # also bash, fish, elvish, powershell";

/// The command-line tool for the gematik Telematikinfrastruktur (TI).
///
/// Offline by default where possible; every command is non-interactive.
#[derive(Debug, Parser)]
#[command(
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
    /// The download cache
    #[command(subcommand)]
    Cache(CacheCommand),
    /// JSON Schema of each command's --format json output; all of them without COMMAND
    Schema {
        /// A command, e.g. "pki verify"
        #[arg(value_name = "COMMAND", num_args = 0..)]
        command: Vec<String>,
    },
    /// How to use this tool from scripts and AI agents (Markdown)
    Agent,
    /// Version and build of this tool
    Version,
    /// Shell completion script for bash, zsh, fish, elvish or powershell
    Completions {
        /// The shell
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },
}

/// `ti cache …`.
#[derive(Debug, Subcommand)]
pub enum CacheCommand {
    /// Delete the downloaded trust material; the next run downloads it again
    Clear,
}

/// `ti pki …`.
#[derive(Debug, Subcommand)]
pub enum PkiCommand {
    /// Decode certificates and show what the TI reads from them (offline; does not validate)
    Inspect {
        /// PEM, DER or PKCS#12 file with one or more certificates; "-" reads stdin
        #[arg(value_name = "FILE")]
        file: PathBuf,
        /// Password of a PKCS#12 file
        #[arg(long, value_name = "PASSWORD", default_value = "00")]
        p12_password: String,
    },
    /// List the validation profiles or show what one requires
    #[command(subcommand)]
    Profiles(ProfilesCommand),
    /// Build the chain to the TI roots and validate it (exit 0 valid, 1 not valid)
    Verify(VerifyArgs),
    /// The roots of an environment: roots.json, verified from the embedded anchor
    #[command(subcommand)]
    Roots(RootsCommand),
    /// The TSL of an environment and the CAs taken from it
    #[command(subcommand)]
    Tsl(TslCommand),
}

/// `ti pki roots …`.
#[derive(Debug, Subcommand)]
pub enum RootsCommand {
    /// List the trusted roots
    List(TrustArgs),
}

/// `ti pki tsl …`.
#[derive(Debug, Subcommand)]
pub enum TslCommand {
    /// The TSL's CAs under the roots that signed them, and those no verified root signed
    Show(TslShowArgs),
}

/// The environment whose trust material a command shows.
#[derive(Debug, Args)]
pub struct TrustArgs {
    /// TI environment
    #[arg(long, value_enum, default_value_t = Environment::Prod, env = "TI_ENV")]
    pub env: Environment,
    /// No network: the cached trust material, else the embedded roots
    #[arg(long)]
    pub offline: bool,
}

/// `ti pki tsl show`. Filters match case-insensitive substrings and combine.
#[derive(Debug, Args)]
pub struct TslShowArgs {
    #[command(flatten)]
    pub trust: TrustArgs,
    /// Only the CAs no verified root signed
    #[arg(long)]
    pub rejected: bool,
    /// Only CAs whose common name contains TEXT; Markdown then includes their PEM
    #[arg(long, value_name = "TEXT")]
    pub ca: Option<String>,
    /// Only CAs of providers whose name contains TEXT
    #[arg(long, value_name = "TEXT")]
    pub provider: Option<String>,
    /// Only CAs under roots whose common name contains TEXT
    #[arg(long, value_name = "TEXT")]
    pub root: Option<String>,
}

/// `ti pki verify`.
#[derive(Debug, Args)]
pub struct VerifyArgs {
    /// PEM, DER or PKCS#12 file, the end entity first (in PKCS#12: the certificate with
    /// its key); further certificates are candidate intermediates; "-" reads stdin
    #[arg(value_name = "FILE")]
    pub file: PathBuf,
    /// Password of PKCS#12 input (FILE, --issuer, --intermediates)
    #[arg(long, value_name = "PASSWORD", default_value = "00")]
    pub p12_password: String,
    /// TI environment; auto detects production or test from the certificates
    #[arg(long, value_enum, default_value_t = Environment::Auto, env = "TI_ENV")]
    pub env: Environment,
    /// Issuing CA certificate (PEM, DER or PKCS#12), when the TSL does not provide it
    #[arg(long, value_name = "FILE")]
    pub issuer: Option<PathBuf>,
    /// Further candidate intermediates (PEM, DER or PKCS#12); repeatable
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

impl Environment {
    /// The environment, or `None` for auto.
    pub fn concrete(self) -> Option<ti_pki::Env> {
        match self {
            Environment::Auto => None,
            Environment::Prod => Some(ti_pki::Env::Prod),
            Environment::Ref => Some(ti_pki::Env::Ref),
            Environment::Test => Some(ti_pki::Env::Test),
            Environment::Dev => Some(ti_pki::Env::Dev),
        }
    }
}

fn profile_selectors() -> PossibleValuesParser {
    PossibleValuesParser::new(ti_pki::profile::selector_values())
}

fn timestamp(value: &str) -> Result<ti_pki::Timestamp, String> {
    ti_pki::Timestamp::parse_rfc3339(value).ok_or_else(|| {
        format!("{value:?} is not an RFC 3339 time with a zone, e.g. 2026-06-01T00:00:00Z")
    })
}

/// `ti pki profiles …`.
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
