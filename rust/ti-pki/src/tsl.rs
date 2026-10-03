//! The Trust Service Status List gematik publishes: the ETSI TS 119 612 XML naming
//! every CA and OCSP responder the TI currently sanctions.
//!
//! [`Tsl::parse`] reads a list without authenticating it;
//! [`Tsl::parse_verified`](crate::tsl_signature) verifies its signature, signer, validity
//! and sequence first (`spec/tsl-xmldsig`), as loading does. Either way the TSL is used as
//! a directory, not as a trust source: it contributes candidate intermediates
//! ([`Tsl::intermediate_cas`]), and a candidate is only kept if a root in the
//! [`TrustStore`] signed it ([`match_to_roots`]).
//!
//! The TSL's per-CA metadata is not used for trust decisions: a SubCA's standing is
//! checked by OCSP at its root's responder, and a certificate's type by its policies
//! rather than by the types the TSL lists per CA.

use core::fmt;

use base64ct::{Base64, Encoding};

use crate::algorithms::AlgorithmSet;
use crate::time::Timestamp;
use crate::{Certificate, Error, TrustStore};

/// Download point of the production TSL.
pub const URL_PROD: &str = "https://download.tsl.ti-dienste.de/ECC/ECC-RSA_TSL.xml";

/// Download point of the reference TSL, which the development environment shares.
pub const URL_REF: &str = "https://download-ref.tsl.ti-dienste.de/ECC/ECC-RSA_TSL-ref.xml";

/// Download point of the test TSL.
pub const URL_TEST: &str = "https://download-test.tsl.ti-dienste.de/ECC/ECC-RSA_TSL-test.xml";

/// `ServiceTypeIdentifier` of a certificate authority.
pub const SERVICE_TYPE_CA_PKC: &str = "http://uri.etsi.org/TrstSvc/Svctype/CA/PKC";

/// `ServiceTypeIdentifier` of an OCSP responder.
pub const SERVICE_TYPE_OCSP: &str = "http://uri.etsi.org/TrstSvc/Svctype/Certstatus/OCSP";

/// The `ServiceStatus` gematik gives every listed service; a CA it no longer sanctions
/// is removed from the list rather than given another status.
pub const SERVICE_STATUS_IN_ACCORD: &str = "http://uri.etsi.org/TrstSvc/Svcstatus/inaccord";

/// The ETSI TS 119 612 v2 name of [`SERVICE_STATUS_IN_ACCORD`].
pub const SERVICE_STATUS_GRANTED: &str = "http://uri.etsi.org/TrstSvc/Svcstatus/granted";

/// A parsed TSL: its sequence, its validity window and every trust service in document
/// order.
#[derive(Clone, Debug)]
pub struct Tsl {
    /// The root element's `Id`, which changes with every issue; empty if absent.
    pub id: String,
    /// `TSLSequenceNumber`, incremented with every issue.
    pub sequence_number: u64,
    /// `ListIssueDateTime`.
    pub issued_at: Timestamp,
    /// `NextUpdate`, by which a new list is published. Absent on a closed list.
    pub next_update: Option<Timestamp>,
    /// Every service of every trust service provider.
    pub services: Vec<Service>,
    /// Services left out because they could not be processed; only a verified list
    /// skips ([`Tsl::parse_verified`](crate::tsl_signature), TSLSIG-052), [`Tsl::parse`]
    /// rejects instead.
    pub skipped: Vec<Skipped>,
}

/// A service of a verified TSL that could not be processed, and why.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Skipped {
    /// The provider's first `TSPName`.
    pub provider: String,
    /// The service's first `ServiceName`, empty if it has none.
    pub name: String,
    /// Why it was left out.
    pub reason: String,
}

/// One trust service of a provider.
#[derive(Clone, Debug)]
pub struct Service {
    /// The provider's first `TSPName`, e.g. `medisign GmbH`.
    pub provider: String,
    /// The first `ServiceName`; gematik uses the certificate's subject DN.
    pub name: String,
    /// `ServiceTypeIdentifier`, e.g. [`SERVICE_TYPE_CA_PKC`].
    pub service_type: String,
    /// `ServiceStatus`, e.g. [`SERVICE_STATUS_IN_ACCORD`].
    pub status: String,
    /// `StatusStartingTime`.
    pub status_starting_time: Option<Timestamp>,
    /// The service's X.509 certificate, if it has one (CVC CAs do not).
    pub certificate: Option<Certificate>,
    /// `ServiceSupplyPoints`; for a CA, the OCSP responder of its certificates.
    pub supply_points: Vec<String>,
}

impl Service {
    /// Whether the status is one under which the service is sanctioned.
    pub fn is_in_accord(&self) -> bool {
        self.status == SERVICE_STATUS_IN_ACCORD || self.status == SERVICE_STATUS_GRANTED
    }
}

impl Tsl {
    /// Parses a TSL document.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] if the document is not a TSL or a date or certificate in it
    /// does not parse. One broken entry rejects the whole list, as in `gempki`: a
    /// partially read list would silently drop CAs.
    pub fn parse(xml: &[u8]) -> Result<Tsl, Error> {
        Tsl::parse_with(xml, false)
    }

    /// As [`Tsl::parse`], but with `skip`, a service that cannot be processed is left
    /// out and recorded in [`Tsl::skipped`] instead of rejecting the list. Only for a
    /// list whose signature verified (TSLSIG-052).
    pub(crate) fn parse_with(xml: &[u8], skip: bool) -> Result<Tsl, Error> {
        let xml = core::str::from_utf8(xml).map_err(|e| malformed(e.to_string()))?;
        let list: xml::TrustServiceStatusList =
            quick_xml::de::from_str(xml).map_err(|e| malformed(e.to_string()))?;
        let scheme = list.scheme_information;
        let mut services = Vec::new();
        let mut skipped = Vec::new();
        for provider in list.provider_list.map(|l| l.providers).unwrap_or_default() {
            let provider_name = first_name(provider.information.name);
            for service in provider.services.map(|s| s.services).unwrap_or_default() {
                let name = first_name(service.information.name.clone());
                match convert(&provider_name, service.information) {
                    Ok(service) => services.push(service),
                    Err(e) if skip => skipped.push(Skipped {
                        provider: provider_name.clone(),
                        name,
                        reason: e.to_string(),
                    }),
                    Err(e) => return Err(e),
                }
            }
        }
        Ok(Tsl {
            id: list.id.unwrap_or_default().trim().to_owned(),
            sequence_number: scheme.sequence_number,
            issued_at: timestamp(&scheme.list_issue_date_time, "ListIssueDateTime")?,
            next_update: scheme
                .next_update
                .and_then(|n| n.date_time)
                .map(|t| timestamp(&t, "NextUpdate"))
                .transpose()?,
            services,
            skipped,
        })
    }

    /// The CA services in accord, in document order, with their providers: the
    /// candidate intermediates. Untrusted until [`match_to_roots`] has kept them.
    pub fn intermediate_cas(&self) -> Vec<Intermediate> {
        self.services
            .iter()
            .filter(|s| s.service_type == SERVICE_TYPE_CA_PKC && s.is_in_accord())
            .filter_map(|s| {
                s.certificate.clone().map(|certificate| Intermediate {
                    certificate,
                    provider: s.provider.clone(),
                })
            })
            .collect()
    }
}

/// A CA the TSL lists, with the trust service provider (TSP) it is listed under.
///
/// The provider groups the CAs of one TSP; OCSP uses it to accept a responder one of
/// the TSP's CAs certified for another of its CAs (see [`crate::ocsp`]). Only the
/// grouping is taken from the TSL: whether the CAs themselves are trusted is decided by
/// [`match_to_roots`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Intermediate {
    /// The CA certificate.
    pub certificate: Certificate,
    /// The provider's `TSPName`, e.g. `gematik GmbH`.
    pub provider: String,
}

/// Candidate intermediates split by whether a root signed them.
#[derive(Clone, Debug, Default)]
pub struct Matched {
    /// CAs issued and signed by a root of the store.
    pub intermediates: Vec<Intermediate>,
    /// The others, with the reason.
    pub rejected: Vec<(Intermediate, Rejection)>,
}

/// Why [`match_to_roots`] did not keep a candidate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Rejection {
    /// Not a CA certificate (no `cA` basic constraint).
    NotCa,
    /// A self-signed CA, which only the TSL vouches for (gematik still lists a few
    /// legacy eGK CAs this way). The TSL does not add trust anchors.
    SelfSigned,
    /// No root in the store has the candidate's issuer as its subject.
    UnknownIssuer,
    /// A root with the issuer's name exists, but none of their signatures verifies.
    BadSignature,
}

impl fmt::Display for Rejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Rejection::NotCa => "not a CA certificate",
            Rejection::SelfSigned => "self-signed, not under a trusted root",
            Rejection::UnknownIssuer => "issuer is not a trusted root",
            Rejection::BadSignature => "signature does not verify under the issuing root",
        })
    }
}

/// Keeps the candidates a root of `store` signed directly; the TI's CA hierarchy is
/// one level deep, root to SubCA. Validity periods are not checked here: path
/// validation reports an expired intermediate with a precise error instead of
/// "incomplete chain".
pub fn match_to_roots(
    candidates: impl IntoIterator<Item = Intermediate>,
    store: &TrustStore,
    algorithms: &AlgorithmSet,
) -> Matched {
    let mut matched = Matched::default();
    for candidate in candidates {
        match check_candidate(&candidate.certificate, store, algorithms) {
            Ok(()) => matched.intermediates.push(candidate),
            Err(reason) => matched.rejected.push((candidate, reason)),
        }
    }
    matched
}

fn check_candidate(
    candidate: &Certificate,
    store: &TrustStore,
    algorithms: &AlgorithmSet,
) -> Result<(), Rejection> {
    if !candidate.is_ca() {
        return Err(Rejection::NotCa);
    }
    if candidate.subject_der() == candidate.issuer_der() {
        return Err(Rejection::SelfSigned);
    }
    // A root rollover keeps the name, so every root with the issuer's name is tried.
    let mut issuers = store
        .roots()
        .iter()
        .filter(|root| root.subject_der() == candidate.issuer_der())
        .peekable();
    if issuers.peek().is_none() {
        return Err(Rejection::UnknownIssuer);
    }
    if issuers.any(|root| candidate.verify_signed_by(root, algorithms).is_ok()) {
        Ok(())
    } else {
        Err(Rejection::BadSignature)
    }
}

fn convert(provider: &str, info: xml::ServiceInformation) -> Result<Service, Error> {
    let name = first_name(info.name);
    let missing = |element: &str| malformed(format!("service {name:?} has no {element}"));
    let service_type = info
        .service_type
        .ok_or_else(|| missing("ServiceTypeIdentifier"))?;
    let status = info.status.ok_or_else(|| missing("ServiceStatus"))?;
    let digital_identity = info
        .digital_identity
        .ok_or_else(|| missing("ServiceDigitalIdentity"))?;
    let certificate = digital_identity
        .digital_ids
        .into_iter()
        .find_map(|id| id.x509_certificate)
        .map(|b64| {
            let der = Base64::decode_vec(&strip_whitespace(&b64))
                .map_err(|e| malformed(format!("certificate of {name:?}: {e}")))?;
            Certificate::from_der(&der)
                .map_err(|e| malformed(format!("certificate of {name:?}: {e}")))
        })
        .transpose()?;
    Ok(Service {
        provider: provider.to_owned(),
        status_starting_time: info
            .status_starting_time
            .map(|t| timestamp(&t, "StatusStartingTime"))
            .transpose()?,
        name,
        service_type: service_type.trim().to_owned(),
        status: status.trim().to_owned(),
        certificate,
        supply_points: info
            .supply_points
            .map(|p| p.points.into_iter().map(|s| s.trim().to_owned()).collect())
            .unwrap_or_default(),
    })
}

fn first_name(names: Option<xml::Names>) -> String {
    names
        .and_then(|n| n.names.into_iter().next())
        .map(|n| n.value.trim().to_owned())
        .unwrap_or_default()
}

fn strip_whitespace(s: &str) -> String {
    s.chars().filter(|c| !c.is_ascii_whitespace()).collect()
}

fn timestamp(value: &str, element: &str) -> Result<Timestamp, Error> {
    Timestamp::parse_rfc3339(value.trim())
        .ok_or_else(|| malformed(format!("{element} {value:?} is not an RFC 3339 dateTime")))
}

fn malformed(reason: String) -> Error {
    Error::Malformed {
        what: "TSL",
        reason,
    }
}

/// The subset of the ETSI TS 119 612 schema the port reads. quick-xml matches element
/// names without their namespace prefix, so the few elements gematik writes with an
/// explicit `ns:` prefix need no special handling; everything else is skipped,
/// including the XMLDSig.
mod xml {
    use serde::Deserialize;

    #[derive(Deserialize)]
    pub(super) struct TrustServiceStatusList {
        #[serde(rename = "@Id")]
        pub(super) id: Option<String>,
        #[serde(rename = "SchemeInformation")]
        pub(super) scheme_information: SchemeInformation,
        #[serde(rename = "TrustServiceProviderList")]
        pub(super) provider_list: Option<ProviderList>,
    }

    #[derive(Deserialize)]
    pub(super) struct SchemeInformation {
        #[serde(rename = "TSLSequenceNumber")]
        pub(super) sequence_number: u64,
        #[serde(rename = "ListIssueDateTime")]
        pub(super) list_issue_date_time: String,
        #[serde(rename = "NextUpdate")]
        pub(super) next_update: Option<NextUpdate>,
    }

    #[derive(Deserialize)]
    pub(super) struct NextUpdate {
        #[serde(rename = "dateTime")]
        pub(super) date_time: Option<String>,
    }

    #[derive(Deserialize)]
    pub(super) struct ProviderList {
        #[serde(rename = "TrustServiceProvider", default)]
        pub(super) providers: Vec<Provider>,
    }

    #[derive(Deserialize)]
    pub(super) struct Provider {
        #[serde(rename = "TSPInformation")]
        pub(super) information: ProviderInformation,
        #[serde(rename = "TSPServices")]
        pub(super) services: Option<Services>,
    }

    #[derive(Deserialize)]
    pub(super) struct ProviderInformation {
        #[serde(rename = "TSPName")]
        pub(super) name: Option<Names>,
    }

    #[derive(Deserialize)]
    pub(super) struct Services {
        #[serde(rename = "TSPService", default)]
        pub(super) services: Vec<ServiceElement>,
    }

    #[derive(Deserialize)]
    pub(super) struct ServiceElement {
        #[serde(rename = "ServiceInformation")]
        pub(super) information: ServiceInformation,
    }

    // Required elements are optional here so that a verified list can skip a service
    // that lacks one instead of failing as a whole (TSLSIG-052).
    #[derive(Deserialize)]
    pub(super) struct ServiceInformation {
        #[serde(rename = "ServiceTypeIdentifier")]
        pub(super) service_type: Option<String>,
        #[serde(rename = "ServiceName")]
        pub(super) name: Option<Names>,
        #[serde(rename = "ServiceDigitalIdentity")]
        pub(super) digital_identity: Option<DigitalIdentity>,
        #[serde(rename = "ServiceStatus")]
        pub(super) status: Option<String>,
        #[serde(rename = "StatusStartingTime")]
        pub(super) status_starting_time: Option<String>,
        #[serde(rename = "ServiceSupplyPoints")]
        pub(super) supply_points: Option<SupplyPoints>,
    }

    #[derive(Clone, Deserialize)]
    pub(super) struct Names {
        #[serde(rename = "Name", default)]
        pub(super) names: Vec<Text>,
    }

    #[derive(Clone, Deserialize)]
    pub(super) struct Text {
        #[serde(rename = "$text", default)]
        pub(super) value: String,
    }

    #[derive(Deserialize)]
    pub(super) struct DigitalIdentity {
        #[serde(rename = "DigitalId", default)]
        pub(super) digital_ids: Vec<DigitalId>,
    }

    #[derive(Deserialize)]
    pub(super) struct DigitalId {
        #[serde(rename = "X509Certificate")]
        pub(super) x509_certificate: Option<String>,
    }

    #[derive(Deserialize)]
    pub(super) struct SupplyPoints {
        #[serde(rename = "ServiceSupplyPoint", default)]
        pub(super) points: Vec<String>,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROD: &[u8] = include_bytes!("../tests/fixtures/tsl/ECC-RSA_TSL.xml");

    #[test]
    fn parses_the_production_tsl() {
        let tsl = Tsl::parse(PROD).unwrap();
        assert_eq!(tsl.id, "ID31033320260913230008Z");
        assert_eq!(tsl.sequence_number, 10333);
        assert_eq!(tsl.issued_at.to_string(), "2026-09-13T23:00:08Z");
        assert_eq!(
            tsl.next_update.map(|t| t.to_string()).as_deref(),
            Some("2026-10-13T23:00:08Z")
        );
        assert_eq!(tsl.services.len(), 231);
        assert!(tsl.services.iter().all(Service::is_in_accord));
        let of_type = |t: &'static str| tsl.services.iter().filter(move |s| s.service_type == t);
        assert_eq!(of_type(SERVICE_TYPE_CA_PKC).count(), 90);
        assert_eq!(of_type(SERVICE_TYPE_OCSP).count(), 115);
        assert!(of_type(SERVICE_TYPE_CA_PKC).all(|s| s.certificate.is_some()));
        assert_eq!(tsl.intermediate_cas().len(), 90);

        let smcb = of_type(SERVICE_TYPE_CA_PKC)
            .find(|s| s.name.starts_with("CN=MESIG.SMCB-CA1,"))
            .unwrap();
        assert_eq!(smcb.provider, "medisign GmbH");
        assert_eq!(
            smcb.certificate.as_ref().unwrap().subject_cn(),
            "MESIG.SMCB-CA1"
        );
        assert_eq!(
            smcb.supply_points,
            ["http://ti-ocsp-smcb.medisign.tsp-smc-b.telematik:8080/ocsp"]
        );
        assert_eq!(
            smcb.status_starting_time.map(|t| t.to_string()).as_deref(),
            Some("2018-06-12T05:32:34Z")
        );
    }

    #[cfg(feature = "brainpool")]
    #[test]
    fn production_cas_are_matched_to_production_roots() {
        let tsl = Tsl::parse(PROD).unwrap();
        let config = crate::TrustConfig::preset_prod();
        let store = crate::roots::load(&config, tsl.issued_at).unwrap().store();
        let matched = match_to_roots(tsl.intermediate_cas(), &store, &config.algorithms);
        let rejected: Vec<String> = matched
            .rejected
            .iter()
            .map(|(ca, reason)| format!("{}: {reason}", ca.certificate.subject_cn()))
            .collect();
        assert_eq!(
            rejected,
            [
                "ATOS.EGK-CA14: self-signed, not under a trusted root",
                "ATOS.EGK-CA203: self-signed, not under a trusted root",
                "TSYSI.SMCB-CA1: issuer is not a trusted root",
                "TSYSI.EGK-CA8: self-signed, not under a trusted root",
                "D-Trust.SMCB-CA1: issuer is not a trusted root",
                "BITMARCK.EGK-CA12: self-signed, not under a trusted root",
            ]
        );
        assert_eq!(matched.intermediates.len(), 84);
    }

    fn b64(cert: &Certificate) -> String {
        Base64::encode_string(cert.der())
    }

    /// A minimal TSL with gematik's quirks: a prefixed element, an extension, a
    /// signature element and base64 wrapped over several lines.
    fn document(services: &str, next_update: &str) -> String {
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#" Id="x" TSLTag="t">
 <SchemeInformation><TSLVersionIdentifier>3</TSLVersionIdentifier>
  <TSLSequenceNumber>7</TSLSequenceNumber>
  <ListIssueDateTime>2026-01-01T00:00:00Z</ListIssueDateTime>
  <NextUpdate>{next_update}</NextUpdate>
 </SchemeInformation>
 <TrustServiceProviderList><TrustServiceProvider>
  <TSPInformation><TSPName><Name xml:lang="DE">Test TSP</Name></TSPName></TSPInformation>
  <TSPServices>{services}</TSPServices>
 </TrustServiceProvider></TrustServiceProviderList>
 <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignatureValue>AA==</ds:SignatureValue></ds:Signature>
</TrustServiceStatusList>"#
        )
    }

    fn service(service_type: &str, status: &str, certificate: &str) -> String {
        let wrapped: Vec<&str> = certificate
            .as_bytes()
            .chunks(64)
            .map(|c| core::str::from_utf8(c).unwrap())
            .collect();
        format!(
            r#"<TSPService><ServiceInformation>
  <ServiceTypeIdentifier>{service_type}</ServiceTypeIdentifier>
  <ServiceName><Name xml:lang="DE">svc</Name></ServiceName>
  <ServiceDigitalIdentity><DigitalId><X509SubjectName>CN=x</X509SubjectName></DigitalId>
   <DigitalId><X509Certificate>
{}
   </X509Certificate></DigitalId></ServiceDigitalIdentity>
  <ServiceStatus>{status}</ServiceStatus>
  <StatusStartingTime>2025-01-01T00:00:00Z</StatusStartingTime>
  <ServiceInformationExtensions><Extension Critical="false">
   <ns:ExtensionOID xmlns:ns="http://uri.etsi.org/02231/v2#">1.2.276.0.76.4.77</ns:ExtensionOID>
  </Extension></ServiceInformationExtensions>
 </ServiceInformation></TSPService>"#,
            wrapped.join("\n")
        )
    }

    #[cfg(feature = "brainpool")]
    #[test]
    fn candidates_are_matched_to_roots() {
        use crate::testing::TestPki;

        let pki = TestPki::new();
        let mut tampered = pki.sub_ca_hba.der().to_vec();
        *tampered.last_mut().unwrap() ^= 1;
        let tampered = Certificate::from_der(&tampered).unwrap();
        let services = [
            service(
                SERVICE_TYPE_CA_PKC,
                SERVICE_STATUS_IN_ACCORD,
                &b64(&pki.sub_ca_hba),
            ),
            service(
                SERVICE_TYPE_CA_PKC,
                SERVICE_STATUS_GRANTED,
                &b64(&pki.ee_arzt),
            ),
            service(
                SERVICE_TYPE_CA_PKC,
                SERVICE_STATUS_IN_ACCORD,
                &b64(&pki.sub_ca_komp),
            ),
            service(
                SERVICE_TYPE_CA_PKC,
                SERVICE_STATUS_IN_ACCORD,
                &b64(&tampered),
            ),
            service(
                SERVICE_TYPE_CA_PKC,
                SERVICE_STATUS_IN_ACCORD,
                &b64(&pki.rogue_root),
            ),
            service(
                SERVICE_TYPE_CA_PKC,
                "http://uri.etsi.org/TrstSvc/Svcstatus/revoked",
                &b64(&pki.sub_ca_mixed),
            ),
            service(
                SERVICE_TYPE_OCSP,
                SERVICE_STATUS_IN_ACCORD,
                &b64(&pki.sub_ca_expired),
            ),
        ]
        .concat();
        let tsl =
            Tsl::parse(document(&services, "<dateTime>2026-02-01T00:00:00Z</dateTime>").as_bytes())
                .unwrap();
        assert_eq!(tsl.sequence_number, 7);
        assert_eq!(
            tsl.next_update,
            Timestamp::parse_rfc3339("2026-02-01T00:00:00Z")
        );
        assert_eq!(tsl.services.len(), 7);
        assert_eq!(tsl.services[0].provider, "Test TSP");
        assert_eq!(tsl.services[0].certificate.as_ref(), Some(&pki.sub_ca_hba));

        let store = TrustStore::new([pki.rca1.clone()]);
        let matched = match_to_roots(tsl.intermediate_cas(), &store, crate::algorithms::DEFAULT);
        let kept: Vec<&Certificate> = matched
            .intermediates
            .iter()
            .map(|i| &i.certificate)
            .collect();
        assert_eq!(kept, [&pki.sub_ca_hba]);
        assert!(
            matched
                .intermediates
                .iter()
                .all(|i| i.provider == "Test TSP")
        );
        let rejected: Vec<(&Certificate, Rejection)> = matched
            .rejected
            .iter()
            .map(|(i, r)| (&i.certificate, *r))
            .collect();
        assert_eq!(
            rejected,
            [
                (&pki.ee_arzt, Rejection::NotCa),
                (&pki.sub_ca_komp, Rejection::UnknownIssuer),
                (&tampered, Rejection::BadSignature),
                (&pki.rogue_root, Rejection::SelfSigned),
            ]
        );
    }

    #[cfg(feature = "brainpool")]
    #[test]
    fn a_closed_list_has_no_next_update() {
        let tsl = Tsl::parse(document("", "").as_bytes()).unwrap();
        assert_eq!(tsl.next_update, None);
        assert!(tsl.services.is_empty());
    }

    #[test]
    fn malformed_documents() {
        for (xml, want) in [
            (b"\xff".to_vec(), "invalid utf-8"),
            (b"<html/>".to_vec(), "SchemeInformation"),
            (
                document("", "<dateTime>tomorrow</dateTime>").into_bytes(),
                "NextUpdate \"tomorrow\" is not an RFC 3339 dateTime",
            ),
            (
                document(
                    &service(SERVICE_TYPE_CA_PKC, SERVICE_STATUS_IN_ACCORD, "AAAA"),
                    "",
                )
                .into_bytes(),
                "certificate of \"svc\"",
            ),
            (
                document(
                    &service(SERVICE_TYPE_CA_PKC, SERVICE_STATUS_IN_ACCORD, "!!"),
                    "",
                )
                .into_bytes(),
                "certificate of \"svc\"",
            ),
        ] {
            let error = Tsl::parse(&xml).unwrap_err().to_string();
            assert!(error.contains(want), "{error:?} lacks {want:?}");
        }
    }

    /// TSLSIG-052: a verified list skips what it cannot process, and an unspecified
    /// service type is no reason to.
    #[test]
    fn a_verified_list_skips_broken_services() {
        let broken_certificate = service(SERVICE_TYPE_CA_PKC, SERVICE_STATUS_IN_ACCORD, "AAAA");
        let unspecified = service(
            "http://uri.etsi.org/TrstSvc/Svctype/unspecified",
            SERVICE_STATUS_IN_ACCORD,
            "",
        )
        .replace(
            "<DigitalId><X509Certificate>\n\n   </X509Certificate></DigitalId>",
            "",
        );
        let no_type = "<TSPService><ServiceInformation><ServiceName><Name>untyped</Name>\
                       </ServiceName><ServiceStatus>s</ServiceStatus></ServiceInformation>\
                       </TSPService>";
        let xml = document(
            &[broken_certificate, unspecified, no_type.to_owned()].concat(),
            "",
        );

        assert!(Tsl::parse(xml.as_bytes()).is_err());
        let tsl = Tsl::parse_with(xml.as_bytes(), true).unwrap();
        assert_eq!(tsl.id, "x");
        assert_eq!(tsl.services.len(), 1);
        assert_eq!(
            tsl.services[0].service_type,
            "http://uri.etsi.org/TrstSvc/Svctype/unspecified"
        );
        let skipped: Vec<(&str, bool)> = tsl
            .skipped
            .iter()
            .map(|s| (s.name.as_str(), s.provider == "Test TSP"))
            .collect();
        assert_eq!(skipped, [("svc", true), ("untyped", true)]);
        assert!(tsl.skipped[1].reason.contains("ServiceTypeIdentifier"));
    }
}
