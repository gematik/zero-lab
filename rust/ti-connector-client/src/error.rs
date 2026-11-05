/*
 * Copyright (Change Date see Readme), gematik GmbH
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be approved by the
 * European Commission – subsequent versions of the EUPL (the "Licence").
 * You may not use this work except in compliance with the Licence.
 *
 * You find a copy of the Licence in the "Licence" file or at
 * https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either expressed or implied.
 * In case of changes by gematik find details in the "Readme" file.
 *
 * See the Licence for the specific language governing permissions and limitations under the Licence.
 *
 * *******
 *
 * For additional notes and disclaimer from gematik and in case of changes by gematik,
 * find details in the "Readme" file.
 */

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
    /// The `.kon` credentials or trust store cannot be used by the transport.
    #[error("configuration: {0}")]
    Config(String),
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
    /// The chosen endpoint is not at the origin of the `.kon` URL. Credentials and
    /// documents go to the endpoint, so the directory does not get to choose another.
    #[error(
        "{service}: the service directory names {endpoint}, which is not the origin of the .kon url {url}"
    )]
    ForeignEndpoint {
        /// The service name.
        service: String,
        /// The endpoint the directory names.
        endpoint: String,
        /// The `.kon` URL.
        url: String,
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

impl Fault {
    /// What to do about the fault: the hint of the first code of the trace that has one.
    pub fn hint(&self) -> Option<&'static str> {
        self.trace.iter().find_map(|t| t.code.and_then(fault_hint))
    }
}

/// What to do about a Konnektor fault, by its gematik error code. Most are about the
/// information model of gemSpec_Kon (Mandant, client system, workplace, card terminal),
/// which the Konnektor's administrator maintains and the `.kon` call context names.
pub fn fault_hint(code: i64) -> Option<&'static str> {
    Some(match code {
        // TAB_KON_514-01: an HBA session of another user ID with a raised security state.
        4018 => {
            "another user ID has entered a PIN on this HBA (comfort signature, or another profile or client system): `connector comfort deactivate CARD` ends a comfort session; for any other, take the card out and put it back"
        }
        4004 => {
            "the Konnektor does not know the .kon mandantId; compare it with the Mandanten in the Konnektor's information model"
        }
        4005 => {
            "the Konnektor does not know the .kon clientSystemId; compare it with the client systems in the Konnektor's information model"
        }
        4006 => {
            "the Konnektor does not know the .kon workplaceId; compare it with the workplaces in the Konnektor's information model"
        }
        4007 => {
            "the Konnektor does not know the card terminal (CtId); the card list names each card's terminal"
        }
        4010 => {
            "the .kon clientSystemId is not assigned to its mandantId in the Konnektor's information model"
        }
        4011 => {
            "the .kon workplaceId is not assigned to its mandantId in the Konnektor's information model"
        }
        4012 => {
            "the card's terminal is not assigned to the .kon mandantId in the Konnektor's information model; the card list names each card's terminal"
        }
        4021 => {
            "the call context is incomplete: the .kon needs mandantId, clientSystemId and workplaceId; some Konnektors answer 4021 for an ID they do not know as well, so compare all three with the Konnektor's information model"
        }
        4053 => {
            "PIN entry for an eGK needs a card terminal assigned locally to the .kon workplaceId; assign the eGK's terminal to that workplace in the Konnektor's information model; the card list names each card's terminal"
        }
        4060 => "the card terminal (PIN pad, display) is busy with another operation; retry",
        4092 => {
            "the card is in a terminal that is not local to the .kon workplaceId, and the workplace has no Remote-PIN-KT; in the Konnektor's information model assign that terminal locally to the workplace or name a Remote-PIN-KT for it, or use a workplaceId the terminal is local to; the card list names each card's terminal"
        }
        4093 => {
            "another client system holds the card in an exclusive session; retry once it is released"
        }
        4204 => {
            "the Konnektor could not authenticate the client system: check the .kon credentials (basic user and password, or the PKCS#12) against the client authentication configured in the Konnektor (ANCL_CAUT_MODE)"
        }
        4263 => {
            "comfort signature is switched off in the Konnektor; an administrator enables it in its management interface"
        }
        _ => return None,
    })
}
