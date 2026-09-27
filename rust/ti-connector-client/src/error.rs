//! The one error type of the crate.

use core::fmt;

use serde::Serialize;
use ti_cache::CacheLookupError;

use crate::soap::TransportError;

/// Why a Konnektor call failed.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The service directory does not offer what the call needs.
    #[error(transparent)]
    Discovery(#[from] DiscoveryError),
    /// No HTTP response.
    #[error("transport: {0}")]
    Transport(TransportError),
    /// An HTTP status other than 200 (or a fault's 500).
    #[error("HTTP {status}: {body}")]
    HttpStatus {
        /// The status.
        status: u16,
        /// The start of the body, for diagnostics.
        body: String,
    },
    /// The Konnektor answered with a SOAP fault.
    #[error(transparent)]
    Fault(Fault),
    /// The response could not be read, or the request not written.
    #[error("decode: {0}")]
    Decode(String),
    /// The cache store failed, or offline with nothing cached.
    #[error("cache: {0}")]
    Cache(String),
}

impl Error {
    /// [`Error::HttpStatus`] with the first 512 bytes of `body`.
    pub(crate) fn http_status(status: u16, body: &[u8]) -> Self {
        let body = String::from_utf8_lossy(&body[..body.len().min(512)])
            .trim()
            .to_owned();
        Error::HttpStatus { status, body }
    }

    pub(crate) fn from_cache(error: CacheLookupError<Error>) -> Self {
        match error {
            CacheLookupError::Origin(error) => error,
            other => Error::Cache(other.to_string()),
        }
    }
}

/// What the service directory lacks.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum DiscoveryError {
    /// The service is not listed.
    #[error("the Konnektor does not offer {service}")]
    NotAdvertised {
        /// The service name.
        service: String,
    },
    /// The service is listed, but in no version this client speaks.
    #[error(
        "{service}: the Konnektor offers {}, this client speaks {}",
        .advertised.join(", "),
        .supported.join(", ")
    )]
    NoSupportedVersion {
        /// The service name.
        service: String,
        /// The versions listed.
        advertised: Vec<String>,
        /// The `major.minor` versions this client has bindings for.
        supported: Vec<String>,
    },
    /// The chosen version lists no endpoint.
    #[error("{service} {version} has no endpoint")]
    NoEndpoint {
        /// The service name.
        service: String,
        /// The chosen version.
        version: String,
    },
}

/// A SOAP fault with the gematik error trace, if the Konnektor sent one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Fault {
    /// `faultcode`, e.g. `soap:Server`.
    pub code: String,
    /// `faultstring`.
    pub message: String,
    /// The entries of the gematik error trace (`tel/error/v2.0`), outermost first.
    pub trace: Vec<TraceEntry>,
}

/// One entry of the gematik error trace. Every field is optional, because Konnektors
/// differ in what they fill in.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TraceEntry {
    /// The gematik error code, e.g. 4008.
    pub code: Option<i64>,
    /// Its description.
    pub error_text: Option<String>,
    /// `Technical`, `Security`, `Infrastructure`, `Business` …
    pub error_type: Option<String>,
    /// `Warning`, `Error`, `Fatal`.
    pub severity: Option<String>,
    /// Event identifier in the Konnektor's log.
    pub event_id: Option<String>,
    /// Component type that raised it.
    pub comp_type: Option<String>,
    /// Free-text detail.
    pub detail: Option<String>,
}

impl fmt::Display for Fault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SOAP fault {}: {}", self.code, self.message)?;
        if let Some(entry) = self.trace.first() {
            let code = entry.code.map(|c| c.to_string());
            let parts: Vec<&str> = [code.as_deref(), entry.error_text.as_deref()]
                .into_iter()
                .flatten()
                .collect();
            write!(f, " ({}", parts.join(" "))?;
            if let Some(detail) = &entry.detail {
                write!(f, ": {detail}")?;
            }
            f.write_str(")")?;
        }
        Ok(())
    }
}

impl core::error::Error for Fault {}
