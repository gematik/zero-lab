//! What can go wrong, and what the IDP said when it refused.

use core::fmt;

use crate::http::TransportError;

/// A failure of the flow.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// No response.
    #[error("{what}: {source}")]
    Transport {
        /// Which request.
        what: &'static str,
        /// The client's error.
        #[source]
        source: TransportError,
    },
    /// The IDP refused, with its structured error (RFC 6749 plus the `gematik_*`
    /// members).
    #[error("IDP refused: {0}")]
    Idp(IdpError),
    /// An unexpected status without an IDP error document.
    #[error("{what}: HTTP {status}")]
    Status {
        /// Which request.
        what: &'static str,
        /// The status.
        status: u16,
    },
    /// A response that is not what the protocol says.
    #[error("{what}: {detail}")]
    Malformed {
        /// Which document.
        what: &'static str,
        /// What is wrong with it.
        detail: String,
    },
    /// A JOSE failure: a signature that does not verify, a key that does not fit, a
    /// token outside the TI profile.
    #[error("{what}: {source}")]
    Jose {
        /// Which token or key.
        what: &'static str,
        /// jwz's error.
        #[source]
        source: jwz::Error,
    },
    /// The identity's signer does not sign the algorithm the IDP requires.
    #[error("the identity signs {found}, the IDP needs {needed}")]
    SignerAlgorithm {
        /// What the signer offers.
        found: String,
        /// What the challenge response must be signed with.
        needed: &'static str,
    },
}

impl Error {
    pub(crate) fn malformed(what: &'static str, detail: impl fmt::Display) -> Error {
        Error::Malformed {
            what,
            detail: detail.to_string(),
        }
    }

    pub(crate) fn jose(what: &'static str) -> impl FnOnce(jwz::Error) -> Error {
        move |source| Error::Jose { what, source }
    }
}

/// The IDP's error document, as a JSON body or as the query of a redirect:
/// `error`, `gematik_error_text`, `gematik_timestamp`, `gematik_uuid`, `gematik_code`.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct IdpError {
    /// The HTTP status it came with; none for a redirect.
    #[serde(skip)]
    pub http_status: Option<u16>,
    /// RFC 6749 `error`, e.g. `invalid_request`.
    pub error: String,
    /// What went wrong, in German, for the user.
    #[serde(default)]
    pub gematik_error_text: Option<String>,
    /// Seconds since the epoch, the IDP's clock.
    #[serde(default)]
    pub gematik_timestamp: Option<i64>,
    /// The IDP's reference for the incident.
    #[serde(default)]
    pub gematik_uuid: Option<String>,
    /// The IDP's error code, e.g. `2012`.
    #[serde(default)]
    pub gematik_code: Option<String>,
}

impl IdpError {
    /// From a JSON body, when it is one.
    pub(crate) fn from_body(status: u16, body: &[u8]) -> Option<IdpError> {
        let mut error: IdpError = serde_json::from_slice(body).ok()?;
        if error.error.is_empty() {
            return None;
        }
        error.http_status = Some(status);
        Some(error)
    }

    /// From the query of a redirect, when it carries `error`.
    pub(crate) fn from_query(pairs: &[(String, String)]) -> Option<IdpError> {
        let get = |name: &str| {
            pairs
                .iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.clone())
        };
        Some(IdpError {
            http_status: None,
            error: get("error")?,
            gematik_error_text: get("gematik_error_text"),
            gematik_timestamp: get("gematik_timestamp").and_then(|t| t.parse().ok()),
            gematik_uuid: get("gematik_uuid"),
            gematik_code: get("gematik_code"),
        })
    }
}

impl fmt::Display for IdpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(status) = self.http_status {
            write!(f, "HTTP {status} ")?;
        }
        f.write_str(&self.error)?;
        if let Some(text) = &self.gematik_error_text {
            write!(f, ": {text}")?;
        }
        if let Some(code) = &self.gematik_code {
            write!(f, " (gematik_code {code}")?;
            if let Some(uuid) = &self.gematik_uuid {
                write!(f, ", {uuid}")?;
            }
            f.write_str(")")?;
        }
        Ok(())
    }
}
