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

//! The response model: read-only projections of the Konnektor's cards, certificates,
//! PINs, status and services as the front ends show them. The types only map: no I/O,
//! no Konnektor call, no clock of their own; whatever is judged at an instant takes it
//! from the caller. With the `serde` feature they serialize to the JSON the `ti` CLI
//! publishes, which its schemas (`ti-cli/schemas/connector-*.json`) describe; the shape
//! is declared here, the format is the host's.

use ti_pki::Timestamp;

use crate::certificates::CardCertificate;
use crate::dotkon::Dotkon;
use crate::sds::{Product, ServiceDirectory};
use crate::types::{
    CertificateExpiration, CertificateVerification, ResourceInformation, SignatureModeInfo,
    SignatureVerificationResult, VersionInfoType,
};
use crate::{BINDINGS, PinType, SignatureFormat};

/// A card in one of the Konnektor's terminals.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Card {
    /// The card handle, valid while the card stays inserted.
    pub handle: String,
    /// E.g. `SMC-B`.
    pub card_type: &'static str,
    /// The card's serial number.
    pub iccsn: Option<String>,
    /// The card terminal's `CtId`.
    pub terminal: String,
    /// The terminal's slot.
    pub slot: i64,
    /// The holder's name.
    pub holder: Option<String>,
    /// The insured's number, on an eGK.
    pub kvnr: Option<String>,
    /// When it was inserted, as the Konnektor states it.
    pub inserted: String,
    /// When its certificates expire, as the Konnektor states it.
    pub certificate_expiration: Option<String>,
    /// `major.minor.revision` of the card's software.
    pub cos_version: Option<String>,
    /// `major.minor.revision` of its object system.
    pub object_system_version: Option<String>,
}

impl Card {
    /// `SMC-B 80276001011699910102`, or the handle for a card without ICCSN.
    pub fn label(&self) -> String {
        let id = self.iccsn.as_deref().unwrap_or(&self.handle);
        format!("{} {id}", self.card_type)
    }
}

impl From<&crate::types::Card> for Card {
    fn from(c: &crate::types::Card) -> Self {
        let v = |v: &VersionInfoType| format!("{}.{}.{}", v.major, v.minor, v.revision);
        Card {
            handle: c.card_handle.clone(),
            card_type: c.card_type.as_str(),
            iccsn: c.iccsn.clone(),
            terminal: c.ct_id.clone(),
            slot: c.slot_id,
            holder: c.card_holder_name.clone(),
            kvnr: c.kvnr.clone(),
            inserted: c.insert_time.clone(),
            certificate_expiration: c.certificate_expiration_date.clone(),
            cos_version: c.card_version.as_ref().map(|cv| v(&cv.cos_version)),
            object_system_version: c
                .card_version
                .as_ref()
                .map(|cv| v(&cv.object_system_version)),
        }
    }
}

/// The Konnektor and the configuration it was reached with.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Info {
    /// The configuration's name, e.g. `default`.
    pub name: String,
    /// The Konnektor's address.
    pub url: String,
    /// The call context.
    pub mandant_id: String,
    /// The call context.
    pub workplace_id: String,
    /// The call context.
    pub client_system_id: String,
    /// The `.kon` file's user ID.
    pub user_id: Option<String>,
    /// `basic`, `pkcs12` or `none`.
    pub credentials: &'static str,
    /// The TI environment the `.kon` file states.
    pub environment: Option<String>,
    /// The Konnektor's product information.
    pub product: Product,
}

impl Info {
    /// The configuration `name` with `dotkon`, and the product `directory` names.
    pub fn new(name: &str, dotkon: &Dotkon, directory: &ServiceDirectory) -> Self {
        Info {
            name: name.to_owned(),
            url: dotkon.url.clone(),
            mandant_id: dotkon.mandant_id.clone(),
            workplace_id: dotkon.workplace_id.clone(),
            client_system_id: dotkon.client_system_id.clone(),
            user_id: dotkon.user_id.clone(),
            credentials: dotkon.credentials.kind(),
            environment: dotkon.env.map(|e| e.to_string()),
            product: directory.product.clone(),
        }
    }
}

/// The services of the service directory.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Services {
    /// The Konnektor's product information.
    pub product: Product,
    /// Each service with its versions.
    pub services: Vec<Service>,
}

/// One service and the versions the Konnektor offers of it.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Service {
    /// E.g. `CardService`.
    pub name: String,
    /// The offered versions.
    pub versions: Vec<Version>,
}

/// One offered version of a service.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Version {
    /// E.g. `8.1.2`.
    pub version: String,
    /// The TLS endpoint, else the plain one.
    pub endpoint: Option<String>,
    /// This crate calls this version: it is the one [`ServiceDirectory::resolve`] picks
    /// for one of the [`BINDINGS`].
    pub used: bool,
}

impl Services {
    /// The services of `directory`, the versions this crate calls marked.
    pub fn new(directory: &ServiceDirectory) -> Self {
        let used: Vec<_> = BINDINGS
            .iter()
            .flat_map(|(service, versions)| versions.iter().map(move |v| (*service, *v)))
            .filter_map(|(service, v)| directory.resolve(service, &[v]).ok())
            .collect();
        Services {
            product: directory.product.clone(),
            services: directory
                .services
                .iter()
                .map(|s| Service {
                    name: s.name.clone(),
                    versions: s
                        .versions
                        .iter()
                        .map(|v| Version {
                            version: v.version.clone(),
                            endpoint: v.endpoint_tls.clone().or_else(|| v.endpoint.clone()),
                            used: used
                                .iter()
                                .any(|b| b.service == s.name && b.version == v.version),
                        })
                        .collect(),
                })
                .collect(),
        }
    }
}

/// A certificate read from a card.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Certificate {
    /// E.g. `C.AUT`.
    pub cert_ref: &'static str,
    /// `ECC` or `RSA`.
    pub crypt: &'static str,
    /// The subject's common name.
    pub subject: String,
    /// The admission's registration number.
    pub telematik_id: Option<String>,
    /// The admission's profession items.
    pub profession: Vec<String>,
    /// RFC 3339, UTC.
    pub not_before: String,
    /// RFC 3339, UTC.
    pub not_after: String,
    /// The end of the validity period, for a view that judges it.
    #[cfg_attr(feature = "serde", serde(skip))]
    pub not_after_at: Timestamp,
    /// `valid`, `expired` or `not_yet_valid` at the instant the caller gave.
    pub validity: &'static str,
    /// The key in words, e.g. `ECDSA brainpoolP256r1`.
    pub key: String,
    /// The certificate as PEM.
    pub pem: String,
}

impl Certificate {
    /// `c` judged at `now`, its key described as `key`.
    pub fn new(c: &CardCertificate, now: Timestamp, key: String) -> Self {
        Certificate {
            cert_ref: c.cert_ref.as_str(),
            crypt: c.crypt.as_str(),
            subject: c.certificate.subject_cn().to_owned(),
            telematik_id: c.telematik_id().map(str::to_owned),
            profession: c
                .admission
                .iter()
                .flat_map(|a| a.profession_items.clone())
                .collect(),
            not_before: c.certificate.not_before().to_string(),
            not_after: c.certificate.not_after().to_string(),
            not_after_at: c.certificate.not_after(),
            validity: ti_pki::model::validity(&c.certificate, now),
            key,
            pem: c.certificate.to_pem(),
        }
    }
}

/// A card and its certificates.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Certificates {
    /// The card.
    pub card: Card,
    /// Its certificates.
    pub certificates: Vec<Certificate>,
}

/// The Konnektor's VPN connections and error conditions.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Status {
    /// The VPN to the TI.
    pub vpn_ti: Option<Vpn>,
    /// The VPN to the secure internet service.
    pub vpn_sis: Option<Vpn>,
    /// The operating state's error conditions, active or not.
    pub errors: Vec<ErrorState>,
}

/// A VPN connection's state.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Vpn {
    /// E.g. `Online`.
    pub status: String,
    /// Since when, as the Konnektor states it.
    pub since: String,
}

/// An error condition of the operating state (gemSpec_Kon TAB_KON_503).
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct ErrorState {
    /// E.g. `EC_CardTerminal_Not_Available`.
    pub condition: String,
    /// `Info`, `Warning`, `Error` or `Fatal`, or a manufacturer's own.
    pub severity: String,
    /// E.g. `Operation`, `Security`, `Infrastructure`.
    #[cfg_attr(feature = "serde", serde(rename = "type"))]
    pub kind: String,
    /// Whether the condition holds now.
    pub active: bool,
    /// Since when, as the Konnektor states it.
    pub since: String,
}

/// What an error condition's severity means.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Severity {
    /// No fault.
    Info,
    /// A fault that does not stop operation.
    Warning,
    /// A fault, or a severity not known: a manufacturer chooses its own for its own
    /// conditions, so one that is not known is not taken lightly.
    Error,
}

impl ErrorState {
    /// The condition's severity by TAB_KON_503, in any case.
    pub fn severity(&self) -> Severity {
        Severity::of(&self.severity)
    }
}

impl Severity {
    /// The severity `text` names (TAB_KON_503), [`Severity::Error`] for one not known.
    pub fn of(text: &str) -> Severity {
        if text.eq_ignore_ascii_case("info") {
            Severity::Info
        } else if text.eq_ignore_ascii_case("warning") {
            Severity::Warning
        } else {
            Severity::Error
        }
    }
}

impl Status {
    /// The Konnektor's state in `info`; empty if it reported none.
    pub fn new(info: ResourceInformation) -> Self {
        let state = info.connector;
        let vpn = |status: &str, since: &str| Vpn {
            status: status.to_owned(),
            since: since.to_owned(),
        };
        Status {
            vpn_ti: state.as_ref().map(|s| {
                vpn(
                    &s.vpn_ti_status.connection_status,
                    &s.vpn_ti_status.timestamp,
                )
            }),
            vpn_sis: state.as_ref().map(|s| {
                vpn(
                    &s.vpn_sis_status.connection_status,
                    &s.vpn_sis_status.timestamp,
                )
            }),
            errors: state
                .into_iter()
                .flat_map(|s| s.operating_state.error_state)
                .map(|e| ErrorState {
                    condition: e.error_condition,
                    severity: e.severity,
                    kind: e.r#type,
                    active: e.value,
                    since: e.valid_from,
                })
                .collect(),
        }
    }
}

/// A card that carries an identity: an HBA's holder or an SMC-B's institution.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Identity {
    /// From the card's C.AUT; none where it cannot be read.
    pub telematik_id: Option<String>,
    /// `HBA` or `SMC-B`.
    pub card_type: &'static str,
    /// The holder's name.
    pub holder: Option<String>,
    /// The card's serial number.
    pub iccsn: Option<String>,
    /// The card handle.
    pub handle: String,
}

impl Identity {
    /// `card` with the Telematik-ID read from it.
    pub fn new(card: &crate::types::Card, telematik_id: Option<String>) -> Self {
        Identity {
            telematik_id,
            card_type: card.card_type.as_str(),
            holder: card.card_holder_name.clone(),
            iccsn: card.iccsn.clone(),
            handle: card.card_handle.clone(),
        }
    }
}

/// When a card's certificate expires.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Expiration {
    /// The card terminal's `CtId`.
    pub terminal: String,
    /// The card handle.
    pub handle: String,
    /// The card's serial number.
    pub iccsn: String,
    /// The subject's common name.
    pub subject: String,
    /// The certificate's serial number.
    pub serial: String,
    /// The expiry date as the Konnektor states it.
    pub validity: String,
}

impl From<CertificateExpiration> for Expiration {
    fn from(e: CertificateExpiration) -> Self {
        Expiration {
            terminal: e.ct_id,
            handle: e.card_handle,
            iccsn: e.iccsn,
            subject: e.subject_common_name,
            serial: e.serial_number,
            validity: e.validity,
        }
    }
}

/// A card with its identity and the state of its user PINs.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct CardDescription {
    /// The card.
    pub card: Card,
    /// From the card's C.AUT, for an HBA or SMC-B.
    pub telematik_id: Option<String>,
    /// The card type's user PINs: whether one must be entered before signing.
    pub pins: Vec<PinStatus>,
}

/// The state of one of a card's user PINs.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct PinStatus {
    /// `PIN.SMC`, `PIN.CH` or `PIN.QES`.
    pub pin: &'static str,
    /// The Konnektor's `PinStatus`: `VERIFIED`, `VERIFIABLE`, `TRANSPORT_PIN`,
    /// `EMPTY_PIN`, `BLOCKED` or `DISABLED`; none when the query failed.
    pub status: Option<&'static str>,
    /// The tries left before the PIN blocks.
    pub left_tries: Option<i64>,
    /// Why the status could not be read.
    pub error: Option<String>,
}

impl PinStatus {
    /// The answer for `pin`: its status, or why it could not be read.
    pub fn new(pin: PinType, status: Result<crate::types::PinStatus, String>) -> Self {
        match status {
            Ok(s) => PinStatus {
                pin: pin.as_str(),
                status: s.pin_status.map(crate::types::PinState::as_str),
                left_tries: s.left_tries,
                error: None,
            },
            Err(error) => PinStatus {
                pin: pin.as_str(),
                status: None,
                left_tries: None,
                error: Some(error),
            },
        }
    }
}

/// The outcome of a PIN verification or change at the card terminal.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct PinOutcome {
    /// The card.
    pub card: Card,
    /// `PIN.SMC`, `PIN.CH` or `PIN.QES`.
    pub pin: &'static str,
    /// `OK`, `REJECTED`, `WASBLOCKED`, `NOWBLOCKED`, `TRANSPORT_PIN` or `ERROR`.
    pub result: &'static str,
    /// The tries left before the PIN blocks.
    pub left_tries: Option<i64>,
}

impl PinOutcome {
    /// Whether the card accepted the PIN.
    pub fn accepted(&self) -> bool {
        self.result == crate::types::PinResult::Ok.as_str()
    }
}

/// The Konnektor's verdict on a certificate: path validation and OCSP.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct CertificateCheck {
    /// The subject's common name.
    pub subject: String,
    /// `VALID`, `INCONCLUSIVE` or `INVALID`.
    pub result: &'static str,
    /// The profession OIDs the Konnektor read from the certificate.
    pub roles: Vec<String>,
    /// The Konnektor's reason for a result other than `VALID`, `code text` each.
    pub errors: Vec<String>,
}

impl CertificateCheck {
    /// The verdict `verification` on `certificate`.
    pub fn new(certificate: &ti_pki::Certificate, verification: CertificateVerification) -> Self {
        let status = verification.verification_status;
        CertificateCheck {
            subject: certificate.subject_cn().to_owned(),
            result: status.verification_result.as_str(),
            roles: verification.role_list.role,
            errors: status
                .error
                .into_iter()
                .flat_map(|e| e.trace)
                .map(|t| format!("{} {}", t.code, t.error_text))
                .collect(),
        }
    }

    /// Whether the certificate is valid.
    pub fn valid(&self) -> bool {
        self.result == crate::types::VerificationResult::Valid.as_str()
    }
}

/// The Konnektor's verdict on a signed document.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct SignatureCheck {
    /// `cades` or `pades`.
    pub format: &'static str,
    /// `VALID`, `INCONCLUSIVE` or `INVALID`.
    pub result: String,
    /// What the verification time is based on, e.g. `SIGNATURE_EMBEDDED_TIMESTAMP`.
    pub timestamp_type: String,
    /// The verification time.
    pub timestamp: String,
}

impl SignatureCheck {
    /// The verdict `result` on a signature of `format`.
    pub fn new(format: SignatureFormat, result: SignatureVerificationResult) -> Self {
        SignatureCheck {
            format: format.as_str(),
            result: result.high_level_result,
            timestamp_type: result.timestamp_type,
            timestamp: result.timestamp,
        }
    }

    /// Whether the signature is valid.
    pub fn valid(&self) -> bool {
        self.result == crate::types::VerificationResult::Valid.as_str()
    }
}

/// An HBA's comfort signature: whether it allows it, and the session of a user ID.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Comfort {
    /// The card.
    pub card: Card,
    /// `ENABLED` or `DISABLED`: whether the HBA allows comfort signature.
    pub comfort_signature: Option<&'static str>,
    /// Signatures a session allows at most.
    pub max_signatures: Option<i64>,
    /// How long a session lasts, as the Konnektor states it (e.g. `PT24H`).
    pub max_duration: Option<String>,
    /// The session of the user ID, if one is active.
    pub session: Option<ComfortSession>,
}

/// A comfort signature session.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct ComfortSession {
    /// `COMFORT` or `PIN`.
    pub mode: &'static str,
    /// Signatures the session still allows.
    pub signatures_left: i64,
    /// How long it still lasts, as the Konnektor states it.
    pub time_left: String,
}

impl Comfort {
    /// `card` with no mode known, as after deactivating.
    pub fn new(card: Card) -> Self {
        Comfort {
            card,
            comfort_signature: None,
            max_signatures: None,
            max_duration: None,
            session: None,
        }
    }

    /// `card` in the signature mode `mode`.
    pub fn with_mode(card: Card, mode: SignatureModeInfo) -> Self {
        Comfort {
            card,
            comfort_signature: Some(mode.comfort_signature_status.as_str()),
            max_signatures: Some(mode.comfort_signature_max),
            max_duration: Some(mode.comfort_signature_timer),
            session: mode.session_info.map(|s| ComfortSession {
                mode: s.signature_mode.as_str(),
                signatures_left: s.count_remaining,
                time_left: s.time_remaining,
            }),
        }
    }
}

/// A certificate read from a card for export.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct ExportedCertificate {
    /// E.g. `C.AUT`.
    pub cert_ref: &'static str,
    /// `ECC` or `RSA`.
    pub crypt: &'static str,
    /// The subject's common name.
    pub subject: String,
    /// The certificate as PEM.
    pub pem: String,
}

impl From<&CardCertificate> for ExportedCertificate {
    fn from(c: &CardCertificate) -> Self {
        ExportedCertificate {
            cert_ref: c.cert_ref.as_str(),
            crypt: c.crypt.as_str(),
            subject: c.certificate.subject_cn().to_owned(),
            pem: c.certificate.to_pem(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// TAB_KON_503: an Info condition is no fault, and a severity not known is an error.
    #[test]
    fn tab_kon_503_a_severity_not_known_is_an_error() {
        assert_eq!(Severity::of("Info"), Severity::Info);
        assert_eq!(Severity::of("INFO"), Severity::Info);
        assert_eq!(Severity::of("Warning"), Severity::Warning);
        for severity in ["Error", "Fatal", "Something new", ""] {
            assert_eq!(Severity::of(severity), Severity::Error);
        }
    }
}
