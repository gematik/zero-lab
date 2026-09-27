//! The command line: global options, HTTP options and the command tree.

use std::path::PathBuf;
use std::time::Duration;

use clap::builder::PossibleValuesParser;
use clap::{ArgAction, Args, Parser, Subcommand, ValueEnum};

use crate::net::NetArgs;

/// Exit codes, variables and examples; `{bin}` stands for [`crate::BIN`].
pub const AFTER_HELP: &str = "\
Exit codes:
  0  success; for verify: the certificate is valid, or the PIN was accepted
  1  the certificate is not valid, or the PIN was not accepted
  2  wrong arguments, options or connector configuration
  3  trust material (roots.json, TSL) unavailable, or the Konnektor failed
  4  input unreadable or without a certificate
  5  output could not be written

Environment:
  TI_FORMAT       default for --format (auto, text, markdown, json)
  TI_ENV          default for verify --env (auto, prod, ref, test, dev)
  TI_CACHE_DIR    default for --cache-dir
  TI_CONNECTOR_CONFIG, TI_CONNECTOR_TIMEOUT, TI_CARD_TIMEOUT
                  defaults for connector -c, --connector-timeout, --card-timeout
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
  {bin} pki inspect identity.p12                # password 00 unless --p12-password
  {bin} pki pkcs12 convert legacy.p12 modern.p12
  {bin} connector configs                       # the .kon files, shared with the Go ti
  {bin} connector -c praxis get cards
  {bin} connector get certificates 80276883110000163974   # ICCSN, Telematik-ID or handle
  {bin} connector verify pin 1-SMC-B-Testkarte-883110000129072
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
    /// The Konnektor: cards, certificates, PINs
    Connector(ConnectorCli),
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
    /// PKCS#12 files: re-encode with modern encryption
    #[command(subcommand)]
    Pkcs12(Pkcs12Command),
}

/// `ti pki pkcs12 …`. `pki inspect` shows what a PKCS#12 file holds.
#[derive(Debug, Subcommand)]
pub enum Pkcs12Command {
    /// Re-encode a PKCS#12 file as DER with PBES2 AES-256 and an SHA-256 MAC, which
    /// OpenSSL 3 and the Go tools read without -legacy
    Convert {
        /// The PKCS#12 file; "-" reads stdin
        #[arg(value_name = "INPUT")]
        input: PathBuf,
        /// Where to write the new file (mode 0600)
        #[arg(value_name = "OUTPUT")]
        output: PathBuf,
        /// Password of INPUT, kept for OUTPUT
        #[arg(long, value_name = "PASSWORD", default_value = "00")]
        p12_password: String,
        /// Replace OUTPUT if it exists
        #[arg(long)]
        force: bool,
    },
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

/// `ti connector …`.
#[derive(Debug, Args)]
pub struct ConnectorCli {
    /// Options of every connector command.
    #[command(flatten)]
    pub args: ConnectorArgs,
    /// What to do.
    #[command(subcommand)]
    pub command: ConnectorCommand,
}

/// Options of every connector command.
#[derive(Debug, Args)]
pub struct ConnectorArgs {
    /// Connector configuration: NAME(.kon) here or in ~/.config/telematik/connectors, or
    /// a path [default: the one `connector use` selected, else "default"]
    #[arg(
        short = 'c',
        long,
        value_name = "NAME|PATH",
        env = "TI_CONNECTOR_CONFIG",
        global = true
    )]
    pub connector_config: Option<String>,
    /// Seconds a Konnektor call may take
    #[arg(long, value_name = "SECS", default_value = "10", value_parser = seconds, env = "TI_CONNECTOR_TIMEOUT", global = true)]
    pub connector_timeout: Duration,
    /// Seconds a call may take that waits for the card terminal (PIN entry, card
    /// cryptography)
    #[arg(long, value_name = "SECS", default_value = "300", value_parser = seconds, env = "TI_CARD_TIMEOUT", global = true)]
    pub card_timeout: Duration,
    /// Load the service directory from the Konnektor instead of the cache
    #[arg(long, global = true)]
    pub no_cache: bool,
}

fn seconds(value: &str) -> Result<Duration, String> {
    match value.parse::<u64>() {
        Ok(secs) if secs > 0 => Ok(Duration::from_secs(secs)),
        _ => Err(format!("{value:?} is not a positive number of seconds")),
    }
}

/// `ti connector …` commands.
#[derive(Debug, Subcommand)]
pub enum ConnectorCommand {
    /// List the .kon files (here and in ~/.config/telematik/connectors)
    Configs,
    /// Select the configuration later commands use without -c
    Use {
        /// NAME or path
        #[arg(value_name = "NAME|PATH")]
        name: String,
    },
    /// Read from the Konnektor
    #[command(subcommand)]
    Get(ConnectorGet),
    /// One card or certificate in detail
    #[command(subcommand)]
    Describe(ConnectorDescribe),
    /// Verify a PIN at the card terminal, or a certificate at the Konnektor (exit 0 or 1)
    #[command(subcommand)]
    Verify(ConnectorVerify),
    /// Change a PIN at the card terminal
    #[command(subcommand)]
    Change(ConnectorChange),
}

/// A card: its ICCSN (20 digits), a Telematik-ID from its C.AUT, or its card handle.
const CARD: &str = "CARD";

/// `ti connector get …`.
#[derive(Debug, Subcommand)]
pub enum ConnectorGet {
    /// The configuration and the Konnektor's product information
    Info,
    /// The services and versions the Konnektor offers, and which this tool uses
    Services,
    /// The cards in the card terminals
    Cards,
    /// The certificates of a card (ECC and RSA)
    Certificates {
        /// ICCSN, Telematik-ID or card handle
        #[arg(value_name = CARD)]
        card: String,
    },
    /// The Konnektor's state: VPN connections and operating errors
    Status,
    /// The Telematik-IDs of the HBAs and SMC-Bs
    Identities,
    /// Certificate expiry dates of a card, or of all cards and the Konnektor
    Expiration {
        /// ICCSN, Telematik-ID or card handle
        #[arg(value_name = CARD)]
        card: Option<String>,
        /// Key type
        #[arg(long, value_enum, default_value_t = CryptArg::Ecc)]
        crypt: CryptArg,
    },
}

/// `ti connector describe …`.
#[derive(Debug, Subcommand)]
pub enum ConnectorDescribe {
    /// A card: type, terminal, versions
    Card {
        /// ICCSN, Telematik-ID or card handle
        #[arg(value_name = CARD)]
        card: String,
    },
    /// A certificate of a card, as `pki inspect` shows it
    Certificate(CardCertificateArgs),
}

/// A certificate on a card.
#[derive(Debug, Args)]
pub struct CardCertificateArgs {
    /// ICCSN, Telematik-ID or card handle
    #[arg(value_name = CARD)]
    pub card: String,
    /// C.AUT, C.ENC, C.SIG or C.QES
    #[arg(value_name = "REF", value_parser = cert_ref)]
    pub cert_ref: ti_connector_client::types::CertRef,
    /// Key type
    #[arg(long, value_enum, default_value_t = CryptArg::Ecc)]
    pub crypt: CryptArg,
}

fn cert_ref(value: &str) -> Result<ti_connector_client::types::CertRef, String> {
    value
        .to_ascii_uppercase()
        .parse()
        .map_err(|_| format!("{value:?} is not C.AUT, C.ENC, C.SIG or C.QES"))
}

/// `--crypt`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum CryptArg {
    /// Elliptic curves (brainpool).
    Ecc,
    /// RSA, on older cards.
    Rsa,
}

impl From<CryptArg> for ti_connector_client::types::Crypt {
    fn from(crypt: CryptArg) -> Self {
        match crypt {
            CryptArg::Ecc => ti_connector_client::types::Crypt::Ecc,
            CryptArg::Rsa => ti_connector_client::types::Crypt::Rsa,
        }
    }
}

/// A PIN of a card.
#[derive(Debug, Args)]
pub struct PinArgs {
    /// ICCSN, Telematik-ID or card handle
    #[arg(value_name = CARD)]
    pub card: String,
    /// PIN.CH, PIN.QES or PIN.SMC; needed only for an HBA, which has two
    #[arg(value_name = "PIN", value_parser = pin_type)]
    pub pin: Option<ti_connector_client::PinType>,
}

fn pin_type(value: &str) -> Result<ti_connector_client::PinType, String> {
    value.parse()
}

/// `ti connector verify …`.
#[derive(Debug, Subcommand)]
pub enum ConnectorVerify {
    /// Enter a PIN at the card terminal (exit 0 accepted, 1 not)
    Pin(PinArgs),
    /// The Konnektor's check of a certificate: path to the TI roots and OCSP (exit 0
    /// valid, 1 not)
    Certificate {
        /// ICCSN, Telematik-ID or card handle; or --file
        #[arg(value_name = CARD, required_unless_present = "file", requires = "cert_ref")]
        card: Option<String>,
        /// C.AUT, C.ENC, C.SIG or C.QES
        #[arg(value_name = "REF", value_parser = cert_ref)]
        cert_ref: Option<ti_connector_client::types::CertRef>,
        /// A certificate from a PEM, DER or PKCS#12 file instead of a card; "-" reads stdin
        #[arg(long, short, value_name = "FILE", conflicts_with = "card")]
        file: Option<PathBuf>,
        /// Password of a PKCS#12 --file
        #[arg(long, value_name = "PASSWORD", default_value = "00")]
        p12_password: String,
        /// Key type of the card certificate
        #[arg(long, value_enum, default_value_t = CryptArg::Ecc)]
        crypt: CryptArg,
        /// Verify at this time instead of the Konnektor's now (RFC 3339)
        #[arg(long, value_name = "TIME", value_parser = timestamp)]
        at: Option<ti_pki::Timestamp>,
    },
}

/// `ti connector change …`.
#[derive(Debug, Subcommand)]
pub enum ConnectorChange {
    /// Change a PIN at the card terminal (exit 0 changed, 1 not)
    Pin(PinArgs),
}
