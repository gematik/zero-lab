//! What can go wrong in a command, and the exit code each failure maps to.

use std::io;
use std::process::ExitCode;

/// The documented exit codes. Agents and scripts branch on these, so a code keeps its
/// meaning across versions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Exit {
    /// Success; for `verify`, the certificate is valid.
    Ok = 0,
    /// The certificate is not valid.
    Invalid = 1,
    /// Wrong arguments or options.
    Usage = 2,
    /// A remote party failed: trust material (roots.json, TSL) could not be obtained, or
    /// the Konnektor did not answer or refused the call.
    Remote = 3,
    /// An input file could not be read or holds no certificate.
    Input = 4,
    /// Output could not be written.
    Output = 5,
}

impl From<Exit> for ExitCode {
    fn from(exit: Exit) -> Self {
        ExitCode::from(exit as u8)
    }
}

/// A failure that ends a command. Each carries a stable `kind` for JSON output and, where
/// the user can act on it, a hint.
#[derive(Debug, thiserror::Error)]
pub enum CliError {
    /// A file or stdin could not be read.
    #[error("cannot read {source_name}: {source}")]
    Read {
        /// The file name, or `<stdin>`.
        source_name: String,
        /// Why.
        #[source]
        source: io::Error,
    },
    /// The input holds no certificate.
    #[error("{source_name}: no certificate found")]
    NoCertificate {
        /// The file name, or `<stdin>`.
        source_name: String,
    },
    /// The input is not a readable certificate.
    #[error("{source_name}: {source}")]
    Certificate {
        /// The file name, or `<stdin>`.
        source_name: String,
        /// Why.
        #[source]
        source: ti_pki::Error,
    },
    /// A PKCS#12 file could not be opened.
    #[error("{source_name}: {source}")]
    Pkcs12 {
        /// The file name, or `<stdin>`.
        source_name: String,
        /// Why.
        #[source]
        source: ti_pkcs12::Error,
    },
    /// An output file exists and `--force` was not given.
    #[error("{0} exists")]
    OutputExists(String),
    /// `--env auto` found no evidence for production or test.
    #[error("cannot tell the TI environment from the certificates: {0}")]
    EnvironmentUndetected(String),
    /// The environment given does not fit the command.
    #[error("{0}")]
    Environment(String),
    /// The trust material of the environment could not be used.
    #[error("trust material unavailable: {0}")]
    Trust(#[source] ti_pki::Error),
    /// roots.json or the TSL could not be loaded or failed verification.
    #[error("trust material unavailable: {0}")]
    TrustLoad(String),
    /// `ti schema` was asked for a command that has none.
    #[error("no JSON schema for {0:?}")]
    UnknownSchema(String),
    /// `pki verify --connect` could not reach the server or finish the handshake.
    #[error("{0}")]
    ServerUnreachable(String),
    /// The HTTP client could not be set up from the options.
    #[error("HTTP setup: {0}")]
    HttpSetup(String),
    /// No cache directory can be derived from the environment.
    #[error("cannot determine the cache directory: {0}")]
    CacheDir(&'static str),
    /// No usable `.kon` file, or one the transport cannot use.
    #[error("{0}")]
    ConnectorConfig(String),
    /// A Konnektor call failed.
    #[error("Konnektor: {0}")]
    Connector(#[source] ti_connector_client::Error),
    /// The Konnektor refused a call for a card it restricts on its SOAP API.
    #[error("Konnektor, {card_type} card: {source}")]
    CardRestricted {
        /// The card type, e.g. `SMC-KT`.
        card_type: String,
        /// The Konnektor's answer.
        #[source]
        source: ti_connector_client::Error,
    },
    /// A PIN type that does not fit the card, or none where the card has two.
    #[error("{0}")]
    PinType(String),
    /// Writing to stdout failed.
    #[error("cannot write output: {0}")]
    Output(#[from] io::Error),
}

impl CliError {
    /// A stable, machine-readable name for the failure.
    pub fn kind(&self) -> &'static str {
        match self {
            CliError::Read { .. } => "input_unreadable",
            CliError::NoCertificate { .. } => "no_certificate",
            CliError::Certificate { .. } => "certificate_malformed",
            CliError::Pkcs12 { source, .. } if source.is_wrong_password() => "p12_password",
            CliError::Pkcs12 { .. } => "p12_unreadable",
            CliError::OutputExists(_) => "output_exists",
            CliError::EnvironmentUndetected(_) => "environment_undetected",
            CliError::Environment(_) => "environment_invalid",
            CliError::Trust(_) | CliError::TrustLoad(_) => "trust_material_unavailable",
            CliError::HttpSetup(_) => "http_setup",
            CliError::ServerUnreachable(_) => "server_unreachable",
            CliError::UnknownSchema(_) => "unknown_schema",
            CliError::CacheDir(_) => "cache_dir_unknown",
            CliError::ConnectorConfig(_)
            | CliError::Connector(ti_connector_client::Error::Config(_)) => "connector_config",
            CliError::Connector(ti_connector_client::Error::Transport(_)) => {
                "connector_unreachable"
            }
            CliError::Connector(ti_connector_client::Error::Fault(_)) => "connector_fault",
            CliError::Connector(ti_connector_client::Error::Discovery(_)) => {
                "connector_unsupported"
            }
            CliError::Connector(_) => "connector_failed",
            CliError::CardRestricted { .. } => "card_restricted",
            CliError::PinType(_) => "pin_type",
            CliError::Output(_) => "output_failed",
        }
    }

    /// What the user can do about it, if anything.
    pub fn hint(&self) -> Option<&'static str> {
        match self {
            CliError::Read { .. } => Some("check the path; use '-' to read from stdin"),
            CliError::NoCertificate { .. } | CliError::Certificate { .. } => {
                Some("expected PEM (-----BEGIN CERTIFICATE-----) or DER")
            }
            CliError::Pkcs12 { source, .. } if source.is_wrong_password() => {
                Some("pass the file's password with --p12-password (default 00)")
            }
            CliError::Pkcs12 { .. } => Some("expected a PKCS#12 (.p12, .pfx) file"),
            CliError::OutputExists(_) => {
                Some("choose another OUTPUT, or pass --force to replace it")
            }
            CliError::EnvironmentUndetected(_) | CliError::Environment(_) => {
                Some("pass --env prod, ref, test or dev")
            }
            CliError::TrustLoad(_) => {
                Some("check the network and the HTTP options (-v shows them), or pass --offline")
            }
            CliError::HttpSetup(_) => Some("check --cacert, --capath and --proxy"),
            CliError::ServerUnreachable(_) => Some(
                "check the host and port, the network and --proxy; or save the chain and pass it as FILE",
            ),
            CliError::UnknownSchema(_) => Some("the schema command without COMMAND lists them all"),
            CliError::CacheDir(_) => Some("set --cache-dir or TI_CACHE_DIR"),
            CliError::ConnectorConfig(_)
            | CliError::Connector(ti_connector_client::Error::Config(_)) => Some(
                "`connector configs` lists the configurations; select one with -c NAME or `connector use NAME`",
            ),
            CliError::Connector(ti_connector_client::Error::Transport(_)) => Some(
                "check the .kon url, the network and the Konnektor's TLS certificate (-v shows each call)",
            ),
            CliError::Connector(ti_connector_client::Error::Fault(fault))
                if fault.trace.iter().any(|t| t.code == Some(4263)) =>
            {
                Some(
                    "comfort signature is switched off in the Konnektor; an administrator enables it in its management interface",
                )
            }
            CliError::Connector(ti_connector_client::Error::Fault(_)) => {
                Some("the Konnektor refused the call; its code and text say why")
            }
            CliError::CardRestricted { .. } => Some(
                "SMC-KT, KVK and eGK are restricted on the Konnektor's SOAP API; use an HBA or SMC-B",
            ),
            CliError::PinType(_) => Some("name the PIN: PIN.CH, PIN.QES or PIN.SMC"),
            CliError::Trust(_) | CliError::Output(_) | CliError::Connector(_) => None,
        }
    }

    /// The exit code the failure ends the process with.
    pub fn exit(&self) -> Exit {
        match self {
            CliError::Read { .. }
            | CliError::NoCertificate { .. }
            | CliError::Certificate { .. }
            | CliError::Pkcs12 { .. } => Exit::Input,
            CliError::EnvironmentUndetected(_)
            | CliError::Environment(_)
            | CliError::OutputExists(_)
            | CliError::HttpSetup(_)
            | CliError::UnknownSchema(_)
            | CliError::CacheDir(_)
            | CliError::PinType(_)
            | CliError::ConnectorConfig(_)
            | CliError::Connector(ti_connector_client::Error::Config(_)) => Exit::Usage,
            CliError::Trust(_)
            | CliError::TrustLoad(_)
            | CliError::ServerUnreachable(_)
            | CliError::Connector(_)
            | CliError::CardRestricted { .. } => Exit::Remote,
            CliError::Output(_) => Exit::Output,
        }
    }

    /// Whether the reader of stdout went away (`ti … | head`), which is not an error.
    pub fn is_broken_pipe(&self) -> bool {
        matches!(self, CliError::Output(e) if e.kind() == io::ErrorKind::BrokenPipe)
    }
}

impl From<serde_json::Error> for CliError {
    fn from(error: serde_json::Error) -> Self {
        CliError::Output(error.into())
    }
}
