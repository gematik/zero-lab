//! A certificate as the TI reads it, without validating it: the report of
//! `ti pki inspect` (`ti-cli/schemas/pki-inspect.json`, `certificates[]`).

use const_oid::ObjectIdentifier;
use serde::Serialize;
use ti_pki::key::classify_key;
use ti_pki::{Certificate, CertificateType, Timestamp, checks, detect_certificate_type, profile};

use crate::{OidInfo, hex, pem, sha256, validity};

/// What a certificate says, for display.
#[derive(Clone, Debug, Serialize)]
pub struct CertificateInfo {
    /// The subject DN, RFC 4514.
    pub subject: String,
    /// In OpenSSL's notation, e.g. `DNS:host`.
    pub subject_alt_names: Vec<String>,
    /// The issuer DN, RFC 4514.
    pub issuer: String,
    /// The serial number in [`hex`].
    pub serial: String,
    /// RFC 3339, UTC.
    pub not_before: String,
    /// RFC 3339, UTC.
    pub not_after: String,
    /// `not_before` as a timestamp, for views.
    #[serde(skip)]
    pub not_before_at: Timestamp,
    /// `not_after` as a timestamp, for views.
    #[serde(skip)]
    pub not_after_at: Timestamp,
    /// `valid`, `expired` or `not_yet_valid`, at the instant described.
    pub validity: &'static str,
    /// The subject key.
    pub key: KeyInfo,
    /// The certificate's signature algorithm, e.g. `ecdsa-with-SHA256`.
    pub signature_algorithm: String,
    /// The Tab_PKI_405 type, e.g. `C.HCI.AUT`, if one is detected.
    pub certificate_type: Option<&'static str>,
    /// The profile it would be validated under.
    pub profile: Option<ProfileHint>,
    /// The admission extension, if present.
    pub admission: Option<AdmissionInfo>,
    /// The certificate policies.
    pub policies: Vec<OidInfo>,
    /// The key usage bits, by RFC 5280 name.
    pub key_usage: Vec<&'static str>,
    /// The extended key usages, by name or OID.
    pub extended_key_usage: Vec<String>,
    /// A CA certificate (`cA` basic constraint).
    pub ca: bool,
    /// The path length constraint of a CA.
    pub path_len: Option<u8>,
    /// The OCSP responders from authority information access.
    pub ocsp_urls: Vec<String>,
    /// The extensions marked critical, by name or OID.
    pub critical_extensions: Vec<String>,
    /// The subject key identifier in [`hex`].
    pub subject_key_id: Option<String>,
    /// The authority key identifier in [`hex`].
    pub authority_key_id: Option<String>,
    /// The SHA-256 fingerprint in [`hex`].
    pub sha256: String,
    /// The certificate as PEM.
    pub pem: String,
}

/// The subject key.
#[derive(Clone, Debug, Serialize)]
pub struct KeyInfo {
    /// In words, e.g. `ECDSA brainpoolP256r1`.
    pub algorithm: String,
    /// gemSpec_Krypt: `admissible`, `phased out`, `not admissible`.
    pub status: &'static str,
}

/// The validation profile the certificate would be checked under.
#[derive(Clone, Debug, Serialize)]
pub struct ProfileHint {
    /// The profile's name, e.g. `smb-aut`.
    pub name: &'static str,
    /// How it was selected, e.g. `default`.
    pub reason: &'static str,
    /// Why, in words.
    pub detail: String,
}

/// The admission extension: who the certificate was issued to, in TI terms.
#[derive(Clone, Debug, Serialize)]
pub struct AdmissionInfo {
    /// The professions in words.
    pub profession_items: Vec<String>,
    /// The profession or institution OIDs.
    pub profession_oids: Vec<OidInfo>,
    /// The registration number, e.g. a Telematik-ID.
    pub registration_number: Option<String>,
}

/// `cert` as the TI reads it, its validity and key status judged at `now`.
pub fn describe(cert: &Certificate, now: Timestamp) -> CertificateInfo {
    let (status, algorithm) = classify_key(cert.public_key_info(), now);
    let selection = profile::select_for_cert(cert);
    let basic = cert.basic_constraints();
    CertificateInfo {
        subject: cert.subject().to_string(),
        subject_alt_names: cert.subject_alt_names(),
        issuer: cert.issuer().to_string(),
        serial: hex(cert.serial()),
        not_before: cert.not_before().to_string(),
        not_after: cert.not_after().to_string(),
        not_before_at: cert.not_before(),
        not_after_at: cert.not_after(),
        validity: validity(cert, now),
        key: KeyInfo {
            algorithm,
            status: status.as_str(),
        },
        signature_algorithm: cert.signature_algorithm(),
        certificate_type: detect_certificate_type(cert).map(CertificateType::as_str),
        profile: selection.profile.map(|p| ProfileHint {
            name: p.name,
            reason: selection.reason.as_str(),
            detail: selection.detail.clone(),
        }),
        admission: cert.admission().ok().flatten().map(|a| AdmissionInfo {
            profession_items: a.profession_items,
            profession_oids: a.profession_oids.iter().map(OidInfo::new).collect(),
            registration_number: a.registration_number,
        }),
        policies: cert.policies().iter().map(OidInfo::new).collect(),
        key_usage: cert
            .key_usage()
            .map(|ku| ku.0.into_iter().map(checks::key_usage_name).collect())
            .unwrap_or_default(),
        extended_key_usage: cert
            .ext_key_usage()
            .iter()
            .map(checks::ext_key_usage_name)
            .collect(),
        ca: cert.is_ca(),
        path_len: basic.and_then(|b| b.path_len_constraint),
        ocsp_urls: cert.ocsp_urls().to_vec(),
        critical_extensions: cert
            .critical_extensions()
            .map(|oid| extension_name(&oid))
            .collect(),
        subject_key_id: cert.subject_key_id().map(hex),
        authority_key_id: cert.authority_key_id().map(hex),
        sha256: sha256(cert.der()),
        pem: pem(cert.der()),
    }
}

/// The RFC 5280 name of the extensions a TI certificate carries; the OID otherwise.
fn extension_name(oid: &ObjectIdentifier) -> String {
    let name = match oid.to_string().as_str() {
        "2.5.29.14" => "subjectKeyIdentifier",
        "2.5.29.15" => "keyUsage",
        "2.5.29.17" => "subjectAltName",
        "2.5.29.19" => "basicConstraints",
        "2.5.29.30" => "nameConstraints",
        "2.5.29.32" => "certificatePolicies",
        "2.5.29.35" => "authorityKeyIdentifier",
        "2.5.29.36" => "policyConstraints",
        "2.5.29.37" => "extKeyUsage",
        "1.3.6.1.5.5.7.1.1" => "authorityInfoAccess",
        "1.3.36.8.3.3" => "admission",
        other => return other.to_owned(),
    };
    name.to_owned()
}
