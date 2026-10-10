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
  TI_ENV          default for --env (auto, prod, ref, test, dev); commands that cannot
                  detect (roots list, tsl show) read auto as prod, probe as unset
  TI_CACHE_DIR    default for --cache-dir
  TI_CONNECTOR_CONFIG, TI_CONNECTOR_TIMEOUT, TI_CARD_TIMEOUT
                  defaults for connector -c, --connector-timeout, --card-timeout
  NO_COLOR        disables colors; CLICOLOR_FORCE=1 forces them

Examples:
  {bin} pki inspect card.pem
  {bin} pki inspect - < card.pem
  {bin} pki inspect card.pem > card.md          # Markdown, as piped output is
  {bin} pki inspect roots.pem --short           # a row per certificate
  {bin} --format json pki inspect card.pem | jq .certificates[0].certificate_type
  {bin} pki profiles describe smb-aut
  {bin} pki verify card.pem --issuer ca.pem
  {bin} pki verify card.pem --env ref --profile none --at 2026-06-01T00:00:00Z
  {bin} pki verify card.pem --ocsp-responder http://ocsp-relay:8080/ --ocsp-max-age 5m
  {bin} pki roots list --env ref
  {bin} pki tsl show --rejected
  {bin} pki tsl show --ca SMCB-CA51 --format markdown   # with the CA's PEM
  {bin} pki tsl verify ECC-RSA_TSL.xml          # signature and signer, env detected
  {bin} pki roots bundle > roots.pem            # CA bundle for curl --cacert, openssl -CAfile
  {bin} pki roots bundle --p12 --p12-password changeit -o roots.p12   # Java truststore
  {bin} pki tsl bundle --ca SMCB -o smcb.pem    # the TSL's CAs, as tsl show filters them
  {bin} pki tsl export -o ECC-RSA_TSL.xml       # the TSL as published, once it verified
  {bin} pki inspect identity.p12                # password 00 unless --p12-password
  {bin} pki pkcs12 convert legacy.p12 modern.p12
  {bin} identity inspect --p12 smcb.p12 --p12-password-path pw.txt   # the AUT identity
  {bin} identity sign --p12 smcb.p12 --claims - < claims.json        # ES256 JWS with x5c
  {bin} identity sign --card 80276883110000163974 --claims c.json   # the selected Konnektor
  {bin} idpd authenticate --env ref --p12 smcb.p12 --auth-url \"$AUTHZ_URI\"   # → code
  {bin} pki verify-signature --cert vau.pem --data keys.cbor --signature sig.bin
  {bin} connector configs                       # the .kon files, shared with the Go ti
  {bin} connector -c praxis get cards
  {bin} connector get certificates 80276883110000163974   # ICCSN, Telematik-ID or handle
  {bin} connector verify pin 1-SMC-B-Testkarte-883110000129072
  {bin} probe ref                               # which TI services of ref answer
  {bin} schema pki verify                       # the JSON contract of one command
  {bin} agent                                   # usage guide for scripts and agents
  {bin} version
  {bin} completions zsh > ~/.zfunc/_{bin}      # also bash, fish, elvish, powershell";

/// The command-line tool for the gematik Telematikinfrastruktur (TI).
///
/// Offline by default where possible; every command is non-interactive.
#[derive(Debug, Parser)]
#[command(
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
    /// The command's `--env` came from `TI_ENV`, not from the command line: a default,
    /// which commands that cannot detect the environment read `auto` of as their own.
    #[arg(skip)]
    pub env_from_variable: bool,
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
    /// An SMC-B identity: its AUT certificate, and signing with its key
    #[command(subcommand)]
    Identity(IdentityCommand),
    /// The gematik IDP-Dienst: authenticate with an identity
    #[command(subcommand)]
    Idpd(IdpdCommand),
    /// The Konnektor: cards, certificates, PINs
    Connector(ConnectorCli),
    /// Check that the TI services of an environment answer, in parallel (exit 0 or 1)
    Probe {
        /// prod, ref, test or dev (also pu, ru, tu); short for --env
        #[arg(value_name = "ENV", value_parser = probe_env)]
        target: Option<ProbeEnv>,
        /// TI environment
        #[arg(long, value_enum, value_name = "ENV", env = "TI_ENV")]
        env: Option<Environment>,
    },
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
    Inspect(InspectArgs),
    /// List the validation profiles or show what one requires
    #[command(subcommand)]
    Profiles(ProfilesCommand),
    /// Build the chain to the TI roots and validate it (exit 0 valid, 1 not valid)
    Verify(VerifyArgs),
    /// Check an ECDSA-SHA256 signature over a file against a certificate's key (exit 0
    /// valid, 1 not valid); the chain is pki verify's business
    VerifySignature(VerifySignatureArgs),
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
    List(RootsArgs),
    /// The trusted roots as a CA bundle: PEM, or a Java truststore with --p12
    Bundle(RootsBundleArgs),
}

/// `ti pki tsl …`.
#[derive(Debug, Subcommand)]
pub enum TslCommand {
    /// The TSL's CAs under the roots that signed them, and those no verified root signed
    Show(TslShowArgs),
    /// Verify a TSL file: its signature and its signer under the TSL signer CA (exit 0
    /// valid, 1 not valid)
    Verify(TslVerifyArgs),
    /// The TSL's CAs a verified root signed, as a CA bundle: PEM, or a Java truststore
    /// with --p12
    Bundle(TslBundleArgs),
    /// The TSL as published, once it verified
    Export(TslExportArgs),
}

/// The environment whose trust material a command shows.
#[derive(Debug, Args)]
pub struct TrustArgs {
    /// TI environment; nothing to detect from here, so auto is only accepted from TI_ENV,
    /// as prod
    #[arg(long, value_enum, default_value_t = Environment::Prod, env = "TI_ENV")]
    pub env: Environment,
    /// No network: the cached trust material, else the embedded roots
    #[arg(long)]
    pub offline: bool,
    /// Verify the trust material at this time instead of now (RFC 3339); the TSL signer's
    /// OCSP status is then not queried
    #[arg(long, value_name = "TIME", value_parser = timestamp)]
    pub at: Option<ti_pki::Timestamp>,
}

/// `ti pki roots list`.
#[derive(Debug, Args)]
pub struct RootsArgs {
    #[command(flatten)]
    pub trust: TrustArgs,
    /// Verify as a client without brainpool would: the roots up to the first brainpool
    /// signature (GEM.RCA7, GEM.RCA6) and no TSL, whose signer CAs are brainpool
    #[arg(long)]
    pub nist_only: bool,
}

/// `ti pki roots bundle`.
#[derive(Debug, Args)]
pub struct RootsBundleArgs {
    #[command(flatten)]
    pub roots: RootsArgs,
    #[command(flatten)]
    pub bundle: BundleArgs,
}

/// Where and how a CA bundle is written.
#[derive(Debug, Args)]
pub struct BundleArgs {
    /// Write to OUT instead of stdout
    #[arg(short, long, value_name = "OUT")]
    pub output: Option<PathBuf>,
    /// Replace OUT if it exists
    #[arg(long)]
    pub force: bool,
    /// A PKCS#12 truststore for Java (each certificate a trustedCertEntry, its alias the
    /// common name) instead of PEM
    #[arg(long, requires = "p12_password")]
    pub p12: bool,
    /// Password of the truststore
    #[arg(long, value_name = "PASSWORD", requires = "p12")]
    pub p12_password: Option<String>,
}

/// Which of the TSL's CAs. Filters match case-insensitive substrings and combine.
#[derive(Debug, Args)]
pub struct CaFilterArgs {
    /// Only CAs whose common name contains TEXT; tsl show's Markdown then includes their PEM
    #[arg(long, value_name = "TEXT")]
    pub ca: Option<String>,
    /// Only CAs of providers whose name contains TEXT
    #[arg(long, value_name = "TEXT")]
    pub provider: Option<String>,
    /// Only CAs under roots whose common name contains TEXT
    #[arg(long, value_name = "TEXT")]
    pub root: Option<String>,
}

/// `ti pki tsl bundle`.
#[derive(Debug, Args)]
pub struct TslBundleArgs {
    #[command(flatten)]
    pub trust: TrustArgs,
    #[command(flatten)]
    pub filter: CaFilterArgs,
    #[command(flatten)]
    pub bundle: BundleArgs,
}

/// `ti pki tsl export`.
#[derive(Debug, Args)]
pub struct TslExportArgs {
    #[command(flatten)]
    pub trust: TrustArgs,
    /// Write to OUT instead of stdout
    #[arg(short, long, value_name = "OUT")]
    pub output: Option<PathBuf>,
    /// Replace OUT if it exists
    #[arg(long)]
    pub force: bool,
}

/// `ti pki tsl show`.
#[derive(Debug, Args)]
pub struct TslShowArgs {
    #[command(flatten)]
    pub trust: TrustArgs,
    /// Only the CAs no verified root signed
    #[arg(long)]
    pub rejected: bool,
    #[command(flatten)]
    pub filter: CaFilterArgs,
}

/// `ti pki tsl verify`: the file against the embedded TSL signer CA of the environment;
/// online, the signer's OCSP status too.
#[derive(Debug, Args)]
pub struct TslVerifyArgs {
    /// The TSL (XML); "-" reads stdin
    #[arg(value_name = "FILE")]
    pub file: PathBuf,
    /// TI environment; auto takes the one whose TSL signer CA issued the signer
    #[arg(long, value_enum, default_value_t = Environment::Auto, env = "TI_ENV")]
    pub env: Environment,
    /// Verify at this time instead of now (RFC 3339, e.g. 2026-06-01T00:00:00+02:00); the
    /// signer's OCSP status is then not queried
    #[arg(long, value_name = "TIME", value_parser = timestamp)]
    pub at: Option<ti_pki::Timestamp>,
    /// No network: the signer's OCSP status is not queried (warning no_ocsp_check)
    #[arg(long)]
    pub offline: bool,
    /// The list used before: this one must have another Id and a greater sequence
    /// number, or be the same list
    #[arg(long, value_name = "FILE")]
    pub previous: Option<PathBuf>,
    /// Days the list may still be used after its NextUpdate, with a warning (0 – 30)
    #[arg(long, value_name = "DAYS", default_value_t = 0,
          value_parser = clap::value_parser!(u8).range(0..=30))]
    pub grace: u8,
}

/// `ti pki verify`.
#[derive(Debug, Args)]
pub struct VerifyArgs {
    /// PEM, DER or PKCS#12 file, the end entity first (in PKCS#12: the certificate with
    /// its key); further certificates are candidate intermediates; "-" reads stdin
    #[arg(
        value_name = "FILE",
        required_unless_present = "connect",
        conflicts_with = "connect"
    )]
    pub file: Option<PathBuf>,
    /// Fetch the chain from this TLS server instead of a file (port 443 by default); the
    /// server must prove it holds the key, and --fqdn defaults to HOST
    #[arg(long, value_name = "HOST[:PORT]", value_parser = crate::peer::target)]
    pub connect: Option<(String, u16)>,
    /// Password of PKCS#12 input (FILE, --issuer, --intermediates).
    #[command(flatten)]
    pub password: P12PasswordArgs,
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
    /// The host the certificate must name if its commonName names one, e.g. the server
    /// you connected to
    #[arg(long, value_name = "NAME")]
    pub fqdn: Option<String>,
    /// Verify as a client without brainpool would: the roots up to the first brainpool
    /// signature (GEM.RCA7, GEM.RCA6) and no TSL, whose signer CAs are brainpool
    #[arg(long)]
    pub nist_only: bool,
    /// Send the chain's OCSP requests to this responder instead of each certificate's
    /// own, e.g. a relay where the TI responders are not reachable directly
    #[arg(long, value_name = "URL", value_parser = http_url, conflicts_with = "offline")]
    pub ocsp_responder: Option<String>,
    /// Accept OCSP responses up to this old (ms, s, m or h, e.g. 5m), for responders
    /// that answer from a cache; default 37.5s
    #[arg(long, value_name = "DURATION", value_parser = duration, conflicts_with = "offline")]
    pub ocsp_max_age: Option<Duration>,
}

/// `ti pki inspect`.
#[derive(Debug, Args)]
pub struct InspectArgs {
    /// PEM, DER or PKCS#12 file with one or more certificates; "-" reads stdin
    #[arg(value_name = "FILE")]
    pub file: PathBuf,
    #[command(flatten)]
    pub password: P12PasswordArgs,
    /// One table row per certificate: subject, expiry, Telematik-ID; JSON stays the full
    /// report
    #[arg(long)]
    pub short: bool,
}

/// The password of PKCS#12 input: given, read from a file, or `00` (gematik's test
/// cards). A given password wins over a file; the file keeps secrets off the command
/// line for callers such as `epa`.
#[derive(Debug, Args)]
pub struct P12PasswordArgs {
    /// Password of PKCS#12 input [default: 00]
    #[arg(long, value_name = "PASSWORD")]
    pub p12_password: Option<String>,
    /// Read the password of PKCS#12 input from this file (its first line), so it stays out
    /// of the command line and the process list
    #[arg(long, value_name = "FILE", env = "TI_P12_PASSWORD_PATH")]
    pub p12_password_path: Option<PathBuf>,
}

/// `ti pki verify-signature`.
#[derive(Debug, Args)]
pub struct VerifySignatureArgs {
    /// The signer's certificate (PEM or DER); "-" reads stdin
    #[arg(long, value_name = "FILE")]
    pub cert: PathBuf,
    /// The signed data, as it was signed (hashed with SHA-256 here)
    #[arg(long, value_name = "FILE")]
    pub data: PathBuf,
    /// The signature: a DER ECDSA-Sig-Value, or r‖s (64 bytes)
    #[arg(long, value_name = "FILE")]
    pub signature: PathBuf,
}

/// `ti identity …`.
#[derive(Debug, Subcommand)]
pub enum IdentityCommand {
    /// Which identity a source yields: the AUT certificate, its Telematik-ID and key
    /// (offline; the Konnektor is asked for the certificate only)
    Inspect(IdentityArgs),
    /// Sign claims as a compact JWS with the identity's key: ES256, x5c the certificate
    Sign(IdentitySignArgs),
}

/// Where the identity comes from: a PKCS#12 file, a PEM certificate and key, or a card
/// at the Konnektor. The AUT certificate is the one with digitalSignature and without
/// contentCommitment whose key is present.
#[derive(Debug, Args)]
#[group(id = "identity_source", required = true, multiple = true)]
pub struct IdentityArgs {
    /// PKCS#12 file with the identity's certificate(s) and key(s), e.g. a test card export
    #[arg(long, value_name = "FILE", group = "identity_source", conflicts_with_all = ["cert", "key", "connector", "card"])]
    pub p12: Option<PathBuf>,
    #[command(flatten)]
    pub password: P12PasswordArgs,
    /// PEM file with the identity's certificate first, then its chain
    #[arg(long, value_name = "FILE", group = "identity_source", requires = "key", conflicts_with_all = ["connector", "card"])]
    pub cert: Option<PathBuf>,
    /// PEM file with the private key (PKCS#8 "PRIVATE KEY" or "EC PRIVATE KEY")
    #[arg(long, value_name = "FILE", requires = "cert")]
    pub key: Option<PathBuf>,
    /// A card at the Konnektor: ICCSN, Telematik-ID or card handle; its C.AUT key signs
    /// through the Konnektor (PIN verified before)
    #[arg(long, value_name = "CARD", group = "identity_source")]
    pub card: Option<String>,
    /// The Konnektor of --card: NAME(.kon) here or in ~/.config/telematik/connectors, or a
    /// path [default: the one `connector use` selected, else "default"]
    #[arg(
        long,
        value_name = "NAME|PATH",
        env = "TI_CONNECTOR_CONFIG",
        requires = "card"
    )]
    pub connector: Option<String>,
}

/// `ti identity sign`.
#[derive(Debug, Args)]
pub struct IdentitySignArgs {
    #[command(flatten)]
    pub identity: IdentityArgs,
    /// The claims, a JSON object; "-" reads stdin
    #[arg(long, value_name = "FILE")]
    pub claims: PathBuf,
    /// The `typ` header
    #[arg(long, value_name = "TYP", default_value = "JWT")]
    pub typ: String,
    /// A further header parameter; VALUE is JSON, or text if it is not; repeatable
    #[arg(long, value_name = "NAME=VALUE")]
    pub header: Vec<String>,
    /// The JWS algorithm name: ES256 (ePA) or BP256R1 (IDP-Dienst), both ECDSA with
    /// SHA-256; BP256R1 needs a brainpoolP256r1 key
    #[arg(long, value_enum, default_value_t = SignAlg::Es256)]
    pub alg: SignAlg,
}

/// `--alg` of `identity sign`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum SignAlg {
    /// `ES256`: RFC 7518's name, which ePA uses with brainpool keys too.
    #[value(name = "ES256")]
    Es256,
    /// `BP256R1`: gematik's name for ECDSA-SHA256 on brainpoolP256r1 (the IDP-Dienst).
    #[value(name = "BP256R1")]
    Bp256r1,
}

/// `ti idpd …`: the gematik IDP-Dienst.
#[derive(Debug, Subcommand)]
pub enum IdpdCommand {
    /// Run the Authenticator-Modul flow for an authorization URL with an identity:
    /// challenge, signed challenge, authorization code (exit 0; 3 when the IDP refuses)
    Authenticate(IdpdAuthenticateArgs),
}

/// `ti idpd authenticate`.
#[derive(Debug, Args)]
pub struct IdpdAuthenticateArgs {
    #[command(flatten)]
    pub identity: IdentityArgs,
    /// The authorization URL the relying party made (for ePA: the Aktensystem's
    /// authz_uri); https, or http on 127.0.0.1 for tests
    #[arg(long, value_name = "URL", value_parser = idp_url)]
    pub auth_url: String,
    /// The TI environment whose IDP-Dienst to use (dev shares ref); auto is not an option
    #[arg(
        long,
        value_enum,
        value_name = "ENV",
        env = "TI_ENV",
        required_unless_present = "idp_url",
        conflicts_with = "idp_url"
    )]
    pub env: Option<Environment>,
    /// Another IDP-Dienst, by base URL (e.g. a reference implementation)
    #[arg(long, value_name = "URL", value_parser = idp_url)]
    pub idp_url: Option<String>,
}

/// An IDP or authorization URL: https, or plain http on the loopback for tests.
fn idp_url(value: &str) -> Result<String, String> {
    let loopback = ["http://127.0.0.1", "http://localhost", "http://[::1]"]
        .iter()
        .any(|prefix| value.starts_with(prefix));
    if value.starts_with("https://") || loopback {
        Ok(value.to_owned())
    } else {
        Err(format!("{value:?} is not an https:// URL"))
    }
}

/// `--ocsp-responder`: OCSP goes over plain HTTP or HTTPS (RFC 6960 Appendix A).
fn http_url(value: &str) -> Result<String, String> {
    if value.starts_with("http://") || value.starts_with("https://") {
        Ok(value.to_owned())
    } else {
        Err(format!("{value:?} is not an http:// or https:// URL"))
    }
}

/// A positive whole number with a unit: `ms`, `s`, `m` or `h`.
fn duration(value: &str) -> Result<Duration, String> {
    let invalid = || format!("{value:?} is not a duration like 500ms, 30s, 5m or 1h");
    let split = value
        .find(|c: char| !c.is_ascii_digit())
        .ok_or_else(invalid)?;
    let (number, unit) = value.split_at(split);
    let n: u64 = number.parse().map_err(|_| invalid())?;
    let millis = match unit {
        "ms" => Some(n),
        "s" => n.checked_mul(1_000),
        "m" => n.checked_mul(60_000),
        "h" => n.checked_mul(3_600_000),
        _ => None,
    };
    match millis {
        Some(ms) if ms > 0 => Ok(Duration::from_millis(ms)),
        _ => Err(invalid()),
    }
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

/// The environment `probe` checks, as typed.
#[derive(Clone, Copy, Debug)]
pub struct ProbeEnv {
    /// The environment probed.
    pub env: ti_pki::Env,
    /// Typed as `def` (an easter egg): a slip for `dev`, probed as dev under a banner.
    pub def: bool,
}

fn probe_env(value: &str) -> Result<ProbeEnv, String> {
    if value.eq_ignore_ascii_case("def") {
        return Ok(ProbeEnv {
            env: ti_pki::Env::Dev,
            def: true,
        });
    }
    env_name(value).map(|env| ProbeEnv { env, def: false })
}

fn env_name(value: &str) -> Result<ti_pki::Env, String> {
    value
        .parse()
        .map_err(|_| format!("{value:?} is not prod, ref, test or dev (or pu, ru, tu)"))
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
        /// Also list the CAs whose entry in this environment's TSL allows the profile's
        /// types (TUC_PKI_007); loads the environment's trust material
        #[arg(long, value_enum, value_name = "ENV")]
        env: Option<Environment>,
        /// With --env: no network, the cached trust material
        #[arg(long, requires = "env")]
        offline: bool,
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
    /// The comfort signature session's user ID, instead of the one `comfort activate`
    /// stored; lets anyone with the same context sign without a PIN, keep it secret
    #[arg(
        long,
        value_name = "UUID",
        env = "TI_COMFORT_USER_ID",
        hide_env_values = true,
        global = true
    )]
    pub comfort_user_id: Option<String>,
}

impl ConnectorArgs {
    /// The options an identity's Konnektor is opened with: configuration `name` (none:
    /// the selected one, else `default`), the default timeouts, the cached service
    /// directory.
    pub fn for_identity(name: Option<&str>) -> Self {
        ConnectorArgs {
            connector_config: name.map(str::to_owned),
            connector_timeout: Duration::from_secs(10),
            card_timeout: Duration::from_secs(300),
            no_cache: false,
            comfort_user_id: None,
        }
    }
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
    /// Sign a file with a card: CAdES (detached, FILE.p7s) or, for a PDF/A, PAdES
    /// (FILE.signed.pdf)
    Sign(SignArgs),
    /// Encrypt a file for the holders of certificates (CMS, FILE.p7m)
    Encrypt(EncryptArgs),
    /// Decrypt a CMS file with a card's C.ENC key
    Decrypt(DecryptArgs),
    /// Comfort signature of an HBA: one PIN.QES entry for many signatures
    #[command(subcommand)]
    Comfort(ConnectorComfort),
    /// Save certificates of a card (PEM to stdout, or a file)
    #[command(subcommand)]
    Export(ConnectorExport),
}

/// `ti connector export …`.
#[derive(Debug, Subcommand)]
pub enum ConnectorExport {
    /// A card's certificate as PEM (or DER); without REF all of them as a PEM bundle
    Certificate(ExportArgs),
}

/// `ti connector export certificate`.
#[derive(Debug, Args)]
pub struct ExportArgs {
    /// ICCSN, Telematik-ID or card handle
    #[arg(value_name = CARD)]
    pub card: String,
    /// C.AUT, C.ENC, C.SIG or C.QES [default: all]
    #[arg(value_name = "REF", value_parser = cert_ref)]
    pub cert_ref: Option<ti_connector_client::types::CertRef>,
    /// Key type [default: ecc with REF, both without]
    #[arg(long, value_enum)]
    pub crypt: Option<CryptArg>,
    /// Write to OUT instead of stdout
    #[arg(short, long, value_name = "OUT")]
    pub output: Option<PathBuf>,
    /// DER instead of PEM (one certificate only)
    #[arg(long, requires = "cert_ref")]
    pub der: bool,
    /// Replace OUT if it exists
    #[arg(long)]
    pub force: bool,
}

/// `ti connector sign`.
#[derive(Debug, Args)]
pub struct SignArgs {
    /// The file to sign; a .pdf must be PDF/A
    #[arg(value_name = "FILE")]
    pub file: PathBuf,
    /// The signing card: ICCSN, Telematik-ID or card handle (SMC-B, or an HBA for a QES)
    #[arg(long, value_name = "CARD")]
    pub card: String,
    /// Signature format [default: pades for .pdf, cades otherwise]
    #[arg(long, value_enum, value_name = "FORMAT")]
    pub signature_format: Option<FormatArg>,
    /// Where to write the signature or signed PDF [default: FILE.p7s or FILE.signed.pdf]
    #[arg(short, long, value_name = "OUT")]
    pub output: Option<PathBuf>,
    /// Media type of FILE [default: from its extension]
    #[arg(long, value_name = "TYPE")]
    pub mime_type: Option<String>,
    /// What the card terminal shows at PIN.QES entry, up to 30 characters; required by
    /// the Konnektor for a qualified signature [default: FILE's name]
    #[arg(long, value_name = "TEXT")]
    pub short_text: Option<String>,
    /// Key type
    #[arg(long, value_enum, default_value_t = CryptArg::Ecc)]
    pub crypt: CryptArg,
    /// Replace OUT if it exists
    #[arg(long)]
    pub force: bool,
}

/// `--signature-format` of `sign`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum FormatArg {
    /// CMS, detached: the signature without the document.
    Cades,
    /// PDF signature in the PDF/A.
    Pades,
}

/// `ti connector encrypt`.
#[derive(Debug, Args)]
pub struct EncryptArgs {
    /// The file to encrypt
    #[arg(value_name = "FILE")]
    pub file: PathBuf,
    /// A recipient's encryption certificate (PEM, DER or PKCS#12); repeatable
    #[arg(
        long = "to",
        value_name = "CERT",
        required_unless_present = "recipient_cards"
    )]
    pub recipients: Vec<PathBuf>,
    /// A card to encrypt for, with its C.ENC (ECC) read from the Konnektor: ICCSN,
    /// Telematik-ID or card handle; repeatable
    #[arg(long = "to-card", value_name = "CARD")]
    pub recipient_cards: Vec<String>,
    /// Password of PKCS#12 recipient files
    #[arg(long, value_name = "PASSWORD", default_value = "00")]
    pub p12_password: String,
    /// Where to write the CMS [default: FILE.p7m]
    #[arg(short, long, value_name = "OUT")]
    pub output: Option<PathBuf>,
    /// Media type of FILE, needed again to decrypt [default: from its extension]
    #[arg(long, value_name = "TYPE")]
    pub mime_type: Option<String>,
    /// Replace OUT if it exists
    #[arg(long)]
    pub force: bool,
}

/// `ti connector decrypt`.
#[derive(Debug, Args)]
pub struct DecryptArgs {
    /// The CMS file
    #[arg(value_name = "FILE")]
    pub file: PathBuf,
    /// The card whose C.ENC key decrypts: ICCSN, Telematik-ID or card handle
    #[arg(long, value_name = "CARD")]
    pub card: String,
    /// Where to write the plaintext (mode 0600) [default: FILE without .p7m]
    #[arg(short, long, value_name = "OUT")]
    pub output: Option<PathBuf>,
    /// Media type of the plaintext, as given to encrypt; the Konnektor checks it
    /// [default: from OUT's extension]
    #[arg(long, value_name = "TYPE")]
    pub mime_type: Option<String>,
    /// Key type
    #[arg(long, value_enum, default_value_t = CryptArg::Ecc)]
    pub crypt: CryptArg,
    /// Replace OUT if it exists
    #[arg(long)]
    pub force: bool,
}

/// `ti connector comfort …`.
#[derive(Debug, Subcommand)]
pub enum ConnectorComfort {
    /// Activate comfort signature (PIN.QES once at the card terminal) with a new random
    /// user ID, kept for later `sign` calls
    Activate {
        /// The HBA: ICCSN, Telematik-ID or card handle
        #[arg(value_name = "CARD")]
        card: String,
    },
    /// Whether comfort signature is enabled, and what is left of the session
    Status {
        /// The HBA: ICCSN, Telematik-ID or card handle
        #[arg(value_name = "CARD")]
        card: String,
    },
    /// End comfort signature and forget the session's user ID
    Deactivate {
        /// The HBA: ICCSN, Telematik-ID or card handle
        #[arg(value_name = "CARD")]
        card: String,
    },
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
    /// The Konnektor's check of a signature: CAdES with --signature, PAdES from the PDF
    /// alone (exit 0 valid, 1 not)
    Signature {
        /// The signed document (for PAdES: the signed PDF)
        #[arg(value_name = "FILE")]
        file: PathBuf,
        /// The detached CAdES signature (.p7s)
        #[arg(long, value_name = "SIG")]
        signature: Option<PathBuf>,
        /// Media type of FILE [default: from its extension]
        #[arg(long, value_name = "TYPE")]
        mime_type: Option<String>,
    },
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

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::duration;

    #[test]
    fn durations_take_a_unit() {
        assert_eq!(duration("1ms"), Ok(Duration::from_millis(1)));
        assert_eq!(duration("30s"), Ok(Duration::from_secs(30)));
        assert_eq!(duration("5m"), Ok(Duration::from_secs(300)));
        assert_eq!(duration("2h"), Ok(Duration::from_secs(7_200)));
        for bad in [
            "",
            "30",
            "s",
            "0s",
            "1.5s",
            "-1s",
            "1d",
            "1 s",
            "99999999999999999h",
        ] {
            assert!(duration(bad).is_err(), "{bad:?}");
        }
    }
}
