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

//! What can go wrong, and what the directory said when it refused.

use core::fmt;

use ti_idpd::http::TransportError;

/// A failure of the owner authentication.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// No response from the directory.
    #[error("FHIR-Directory {what}: {source}")]
    Transport {
        /// Which request.
        what: &'static str,
        /// The client's error.
        #[source]
        source: TransportError,
    },
    /// The directory refused, with its error document.
    #[error("FHIR-Directory refused: {0}")]
    Directory(DirectoryError),
    /// An unexpected status without an error document; what the body said, if it is
    /// text.
    #[error("FHIR-Directory {what}: HTTP {status}{}", body.as_deref().map(|b| format!(": {b}")).unwrap_or_default())]
    Status {
        /// Which request.
        what: &'static str,
        /// The status.
        status: u16,
        /// The body, when it is printable text (whitespace collapsed, at most a few
        /// hundred characters).
        body: Option<String>,
    },
    /// A response that is not what the specification says, or a redirect to a place
    /// the client must not sign for.
    #[error("FHIR-Directory {what}: {detail}")]
    Malformed {
        /// Which step.
        what: &'static str,
        /// What is wrong.
        detail: String,
    },
    /// The directory's Keycloak refused the client credentials.
    #[error("FHIR-Directory Keycloak refused: {0}")]
    AuthServer(OAuthError),
    /// A client-credentials path without a Keycloak URL.
    #[error("FHIR-Directory: no Keycloak URL for the {0} endpoint")]
    NoAuthUrl(&'static str),
    /// The IDP-Dienst flow failed.
    #[error(transparent)]
    Idpd(#[from] ti_idpd::Error),
}

/// An OAuth error document (RFC 6749 §5.2): Keycloak's answer to bad client
/// credentials.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct OAuthError {
    /// The HTTP status it came with.
    #[serde(skip)]
    pub http_status: u16,
    /// `invalid_client`, `unauthorized_client`, …
    pub error: String,
    /// What went wrong.
    #[serde(default)]
    pub error_description: Option<String>,
}

impl OAuthError {
    /// From a JSON body, when it is one with an `error`.
    pub(crate) fn from_body(status: u16, body: &[u8]) -> Option<OAuthError> {
        let mut error: OAuthError = serde_json::from_slice(body).ok()?;
        if error.error.is_empty() {
            return None;
        }
        error.http_status = status;
        Some(error)
    }
}

impl fmt::Display for OAuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HTTP {} {}", self.http_status, self.error)?;
        if let Some(description) = &self.error_description {
            write!(f, ": {description}")?;
        }
        Ok(())
    }
}

impl Error {
    pub(crate) fn status(what: &'static str, status: u16, body: &[u8]) -> Error {
        Error::Status {
            what,
            status,
            body: excerpt(body),
        }
    }

    pub(crate) fn malformed(what: &'static str, detail: impl fmt::Display) -> Error {
        Error::Malformed {
            what,
            detail: detail.to_string(),
        }
    }
}

fn null_is_empty<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<AttributeError>, D::Error> {
    use serde::Deserialize as _;
    Ok(Option::deserialize(deserializer)?.unwrap_or_default())
}

/// `body` as one line of text, when it is text; HTML tags dropped.
fn excerpt(body: &[u8]) -> Option<String> {
    const MAX: usize = 300;
    let text = core::str::from_utf8(body).ok()?;
    let mut out = String::new();
    let mut in_tag = false;
    let mut last_space = true;
    for c in text.chars() {
        match c {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if in_tag => {}
            c if c.is_whitespace() || c.is_control() => {
                if !last_space {
                    out.push(' ');
                    last_space = true;
                }
            }
            c => {
                out.push(c);
                last_space = false;
            }
        }
        if out.len() >= MAX {
            out.push('…');
            break;
        }
    }
    let out = out.trim().to_owned();
    (!out.is_empty()).then_some(out)
}

/// The directory's error document (`I_VZD_Owner`'s `Error`): a message and the
/// attributes it found fault with.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct DirectoryError {
    /// The HTTP status it came with.
    #[serde(skip)]
    pub http_status: u16,
    /// What went wrong, when the directory says.
    #[serde(default)]
    pub message: Option<String>,
    /// The attributes with their faults; the directory sends `null` for none.
    #[serde(default, deserialize_with = "null_is_empty")]
    pub errors: Vec<AttributeError>,
}

/// One attribute the directory found fault with.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct AttributeError {
    /// The attribute.
    #[serde(rename = "attributeName", default)]
    pub attribute_name: Option<String>,
    /// The fault.
    #[serde(rename = "attributeError", default)]
    pub attribute_error: Option<String>,
}

impl DirectoryError {
    /// From a JSON body, when it is one; an empty document still names the status.
    pub(crate) fn from_body(status: u16, body: &[u8]) -> Option<DirectoryError> {
        let mut error: DirectoryError = serde_json::from_slice(body).ok()?;
        error.http_status = status;
        Some(error)
    }
}

impl fmt::Display for DirectoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HTTP {}", self.http_status)?;
        if let Some(message) = &self.message {
            write!(
                f,
                " {}",
                message.split_whitespace().collect::<Vec<_>>().join(" ")
            )?;
        }
        for error in &self.errors {
            match (&error.attribute_name, &error.attribute_error) {
                (Some(name), Some(detail)) => write!(f, "; {name}: {detail}")?,
                (Some(name), None) => write!(f, "; {name}")?,
                (None, Some(detail)) => write!(f, "; {detail}")?,
                (None, None) => {}
            }
        }
        Ok(())
    }
}
