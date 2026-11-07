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

//! What ti-client reports. A front end maps each variant to its own messages and exit
//! codes; the strings carried are the details, written for a person.

use core::fmt;

/// Why an operation of this crate failed.
#[derive(Debug)]
pub enum Error {
    /// The HTTP settings: an unusable proxy, CA file or directory.
    Setup(String),
    /// A Konnektor's `.kon` file, credentials or trust store, or a call to it.
    Connector(ti_connector_client::Error),
    /// No usable `.kon` file: not found, not valid, or a value in it that cannot be used.
    ConnectorConfig(String),
    /// The Konnektor refused a call about a card of a type it restricts on its SOAP API
    /// ([`ti_connector_client::is_restricted`]).
    CardRestricted {
        /// The card type, e.g. `SMC-KT`.
        card_type: String,
        /// The Konnektor's answer.
        source: ti_connector_client::Error,
    },
    /// A PIN that does not fit the card, or none named where the card has several.
    PinType(ti_connector_client::UnfitPin),
    /// A change of a `.kon` file its rules refuse, or a value that cannot be set.
    Refused(String),
    /// A file could not be written; the error names it.
    Write(std::io::Error),
    /// The input holds no certificate.
    NoCertificate {
        /// The input's name, e.g. its file.
        source_name: String,
    },
    /// The input is not a readable certificate.
    Certificate {
        /// The input's name.
        source_name: String,
        /// Why.
        source: ti_pki::Error,
    },
    /// A PKCS#12 file could not be opened or written.
    Pkcs12 {
        /// The file's name.
        source_name: String,
        /// Why.
        source: ti_pkcs12::Error,
    },
    /// The certificates give no evidence for production or test.
    EnvironmentUndetected(String),
    /// The trust material of the environment could not be used.
    Trust(ti_pki::Error),
    /// roots.json or the TSL could not be loaded or failed verification.
    TrustLoad(String),
    /// A TSL verified but does not follow the one kept from an earlier run (TSLSIG-053):
    /// apart from [`Error::TrustLoad`], since the network is not what to look at.
    TslRollback(String),
    /// A TLS server could not be reached or did not finish the handshake.
    ServerUnreachable(String),
    /// The download cache could not be opened, read, written or cleared.
    Cache {
        /// The cache directory or file.
        path: String,
        /// What went wrong.
        reason: String,
    },
    /// A state file, such as the TSL state, could not be read, parsed or written.
    State {
        /// The file.
        path: String,
        /// What went wrong.
        reason: String,
    },
    /// The source holds no authentication certificate together with its key.
    IdentityNotFound(String),
    /// A key that is not ECDSA on brainpoolP256r1 or P-256, or that does not sign what is
    /// asked of it.
    KeyUnsupported(String),
    /// Signing failed for a reason other than the Konnektor refusing.
    Signing(String),
    /// A signature that is neither DER nor the curve's r‖s.
    SignatureMalformed(String),
    /// The system's randomness, which salts and IVs come from, failed.
    Randomness,
    /// The IDP-Dienst refused, did not answer, or answered outside the protocol.
    Idpd(ti_idpd_client::Error),
    /// The FHIR-Directory refused, did not answer, or answered outside the protocol; a
    /// failure of the IDP-Dienst flow inside it is [`Error::Idpd`].
    Directory(Box<ti_directory_client::Error>),
    /// The endpoints a probe was given are not a JSON object of endpoint lists by
    /// environment.
    ProbeEndpoints(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Setup(message)
            | Error::EnvironmentUndetected(message)
            | Error::TrustLoad(message)
            | Error::TslRollback(message)
            | Error::ServerUnreachable(message)
            | Error::IdentityNotFound(message)
            | Error::KeyUnsupported(message)
            | Error::Signing(message)
            | Error::SignatureMalformed(message)
            | Error::ConnectorConfig(message)
            | Error::Refused(message) => f.write_str(message),
            Error::Connector(error) => error.fmt(f),
            Error::CardRestricted { card_type, source } => {
                write!(f, "{card_type} card: {source}")
            }
            Error::PinType(error) => error.fmt(f),
            Error::Write(error) => error.fmt(f),
            Error::NoCertificate { source_name } => {
                write!(f, "{source_name}: no certificate found")
            }
            Error::Certificate {
                source_name,
                source,
            } => write!(f, "{source_name}: {source}"),
            Error::Pkcs12 {
                source_name,
                source,
            } => write!(f, "{source_name}: {source}"),
            Error::Trust(error) => error.fmt(f),
            Error::Cache { path, reason } => write!(f, "cache {path}: {reason}"),
            Error::State { path, reason } => write!(f, "state file {path}: {reason}"),
            Error::Randomness => f.write_str("no system randomness"),
            Error::Idpd(error) => error.fmt(f),
            Error::Directory(error) => error.fmt(f),
            Error::ProbeEndpoints(message) => write!(f, "probe endpoints: {message}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Connector(error) | Error::CardRestricted { source: error, .. } => Some(error),
            Error::PinType(error) => Some(error),
            Error::Write(error) => Some(error),
            Error::Certificate { source, .. } | Error::Trust(source) => Some(source),
            Error::Pkcs12 { source, .. } => Some(source),
            Error::Idpd(error) => Some(error),
            Error::Directory(error) => Some(error),
            _ => None,
        }
    }
}
