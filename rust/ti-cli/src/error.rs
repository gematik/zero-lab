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
    /// Trust material (roots.json, TSL) could not be obtained.
    TrustUnavailable = 3,
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
    /// `--env auto` found no evidence for production or test.
    #[error("cannot tell the TI environment from the certificates: {0}")]
    EnvironmentUndetected(String),
    /// The trust material of the environment could not be used.
    #[error("trust material unavailable: {0}")]
    Trust(#[source] ti_pki::Error),
    /// roots.json or the TSL could not be loaded or failed verification.
    #[error("trust material unavailable: {0}")]
    TrustLoad(String),
    /// `ti schema` was asked for a command that has none.
    #[error("no JSON schema for {0:?}")]
    UnknownSchema(String),
    /// The HTTP client could not be set up from the options.
    #[error("HTTP setup: {0}")]
    HttpSetup(String),
    /// No cache directory can be derived from the environment.
    #[error("cannot determine the cache directory: {0}")]
    CacheDir(&'static str),
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
            CliError::EnvironmentUndetected(_) => "environment_undetected",
            CliError::Trust(_) | CliError::TrustLoad(_) => "trust_material_unavailable",
            CliError::HttpSetup(_) => "http_setup",
            CliError::UnknownSchema(_) => "unknown_schema",
            CliError::CacheDir(_) => "cache_dir_unknown",
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
            CliError::EnvironmentUndetected(_) => Some("pass --env prod, ref, test or dev"),
            CliError::TrustLoad(_) => {
                Some("check the network and the HTTP options (-v shows them), or pass --offline")
            }
            CliError::HttpSetup(_) => Some("check --cacert, --capath and --proxy"),
            CliError::UnknownSchema(_) => Some("the schema command without COMMAND lists them all"),
            CliError::CacheDir(_) => Some("set --cache-dir or TI_CACHE_DIR"),
            CliError::Trust(_) | CliError::Output(_) => None,
        }
    }

    /// The exit code the failure ends the process with.
    pub fn exit(&self) -> Exit {
        match self {
            CliError::Read { .. }
            | CliError::NoCertificate { .. }
            | CliError::Certificate { .. } => Exit::Input,
            CliError::EnvironmentUndetected(_)
            | CliError::HttpSetup(_)
            | CliError::UnknownSchema(_)
            | CliError::CacheDir(_) => Exit::Usage,
            CliError::Trust(_) | CliError::TrustLoad(_) => Exit::TrustUnavailable,
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
