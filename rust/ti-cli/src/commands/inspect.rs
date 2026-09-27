//! `ti pki inspect`: what the TI reads from a certificate, without validating it.

use std::path::Path;

use serde::Serialize;
use sha2::{Digest, Sha256};
use ti_pki::key::{KeyStatus, classify_key};
use ti_pki::load::SystemClock;
use ti_pki::{CertificateType, Clock, Timestamp, checks, detect_certificate_type, profile};
use x509_cert::der::oid::ObjectIdentifier;

use crate::error::{CliError, Exit};
use crate::input;
use crate::output::document::{span, when};
use crate::output::{Document, Line, OidInfo, Output, SCHEMA, Tone, hex, pem};

/// The JSON document.
#[derive(Serialize)]
struct Report {
    schema: u32,
    source: String,
    certificates: Vec<CertificateInfo>,
    /// The container, when the input is a PKCS#12 file.
    pkcs12: Option<Pkcs12Info>,
    /// The instant validity was judged at, for the remaining-time text.
    #[serde(skip)]
    now: Timestamp,
}

#[derive(Serialize)]
struct Pkcs12Info {
    /// `DER`, or `BER` as Java keystores and card vendors write it.
    encoding: &'static str,
    mac: Option<MacInfo>,
    /// The encryption of each encrypted safe and shrouded key, in file order.
    encryption: Vec<EncryptionInfo>,
    keys: Vec<P12KeyInfo>,
}

#[derive(Serialize)]
struct EncryptionInfo {
    /// `certificates` (an encrypted safe) or `key` (a shrouded key).
    target: &'static str,
    algorithm: String,
}

#[derive(Serialize)]
struct MacInfo {
    digest: String,
    iterations: u32,
}

#[derive(Serialize)]
struct P12KeyInfo {
    /// `EC`, `RSA`, or the algorithm OID.
    algorithm: String,
    /// The named curve of an EC key, e.g. `brainpoolP256r1`.
    curve: Option<String>,
    friendly_name: Option<String>,
    local_key_id: Option<String>,
    /// Index into `certificates` of the certificate this key belongs to.
    certificate: Option<usize>,
}

#[derive(Serialize)]
struct CertificateInfo {
    subject: String,
    issuer: String,
    serial: String,
    not_before: String,
    not_after: String,
    #[serde(skip)]
    not_before_at: Timestamp,
    #[serde(skip)]
    not_after_at: Timestamp,
    /// `valid`, `expired` or `not_yet_valid`, now.
    validity: &'static str,
    key: KeyInfo,
    signature_algorithm: String,
    certificate_type: Option<&'static str>,
    profile: Option<ProfileHint>,
    admission: Option<AdmissionInfo>,
    policies: Vec<OidInfo>,
    key_usage: Vec<&'static str>,
    extended_key_usage: Vec<String>,
    ca: bool,
    path_len: Option<u8>,
    ocsp_urls: Vec<String>,
    critical_extensions: Vec<String>,
    subject_key_id: Option<String>,
    authority_key_id: Option<String>,
    sha256: String,
    /// The input is a PKCS#12 file that also holds this certificate's private key.
    private_key: bool,
    /// The `friendlyName` of its bag, in a PKCS#12 file.
    friendly_name: Option<String>,
    /// The `localKeyId` of its bag, in a PKCS#12 file.
    local_key_id: Option<String>,
    pem: String,
}

#[derive(Serialize)]
struct KeyInfo {
    algorithm: String,
    /// gemSpec_Krypt: `admissible`, `phased out`, `not admissible`.
    status: &'static str,
}

#[derive(Serialize)]
struct ProfileHint {
    name: &'static str,
    reason: &'static str,
    detail: String,
}

#[derive(Serialize)]
struct AdmissionInfo {
    profession_items: Vec<String>,
    profession_oids: Vec<OidInfo>,
    registration_number: Option<String>,
}

pub fn run(file: &Path, p12_password: &str, out: &Output) -> Result<Exit, CliError> {
    let source = input::read(file)?;
    let input = input::load(&source, p12_password)?;
    let now = SystemClock.now();
    let certificates: Vec<CertificateInfo> = input
        .certificates
        .iter()
        .map(|loaded| describe(loaded, now))
        .collect();
    let pkcs12 = input
        .pkcs12
        .as_ref()
        .map(|p12| container(&source.bytes, p12, &certificates));
    let report = Report {
        schema: SCHEMA,
        source: source.name,
        certificates,
        pkcs12,
        now,
    };
    if out.is_json() {
        out.json(&report)?;
    } else {
        out.render_views(&sections(&report), &summary(&report))?;
    }
    Ok(Exit::Ok)
}

/// What the PKCS#12 container says beyond its certificates: encoding, protection, and
/// its keys with the certificate each belongs to.
fn container(bytes: &[u8], p12: &ti_pkcs12::Pkcs12, certs: &[CertificateInfo]) -> Pkcs12Info {
    let keys = p12
        .keys
        .iter()
        .map(|key| {
            let (algorithm, curve) = key
                .algorithm()
                .map_or((String::from("unknown"), None), |(a, c)| {
                    (algorithm_name(&a), c.map(|c| curve_name(&c)))
                });
            let local_key_id = key.local_key_id.as_deref().map(hex_id);
            P12KeyInfo {
                algorithm,
                curve,
                friendly_name: key.friendly_name.clone(),
                certificate: local_key_id.as_ref().and_then(|id| {
                    certs
                        .iter()
                        .position(|c| c.local_key_id.as_ref() == Some(id))
                }),
                local_key_id,
            }
        })
        .collect();
    Pkcs12Info {
        encoding: if bytes.get(1) == Some(&0x80) {
            "BER"
        } else {
            "DER"
        },
        mac: p12.mac.as_ref().map(|mac| MacInfo {
            digest: mac.digest.clone(),
            iterations: mac.iterations,
        }),
        encryption: p12
            .encryption
            .iter()
            .map(|e| EncryptionInfo {
                target: if e.target == ti_pkcs12::Target::Key {
                    "key"
                } else {
                    "certificates"
                },
                algorithm: e.algorithm.clone(),
            })
            .collect(),
        keys,
    }
}

/// `localKeyId`s are opaque bytes; lower-case hex without separators, as OpenSSL
/// prints them compactly.
fn hex_id(bytes: &[u8]) -> String {
    hex(bytes).replace(':', "").to_lowercase()
}

fn algorithm_name(oid: &ObjectIdentifier) -> String {
    match oid.to_string().as_str() {
        "1.2.840.10045.2.1" => "EC".to_owned(),
        "1.2.840.113549.1.1.1" => "RSA".to_owned(),
        other => other.to_owned(),
    }
}

fn curve_name(oid: &ObjectIdentifier) -> String {
    match oid.to_string().as_str() {
        "1.3.36.3.3.2.8.1.1.7" => "brainpoolP256r1".to_owned(),
        "1.3.36.3.3.2.8.1.1.11" => "brainpoolP384r1".to_owned(),
        "1.3.36.3.3.2.8.1.1.13" => "brainpoolP512r1".to_owned(),
        "1.2.840.10045.3.1.7" => "P-256".to_owned(),
        "1.3.132.0.34" => "P-384".to_owned(),
        "1.3.132.0.35" => "P-521".to_owned(),
        other => other.to_owned(),
    }
}

fn describe(loaded: &input::Loaded, now: Timestamp) -> CertificateInfo {
    let cert = &loaded.certificate;
    let private_key = loaded.private_key;
    let (friendly_name, local_key_id) = loaded.bag.as_ref().map_or((None, None), |(name, id)| {
        (name.clone(), id.as_deref().map(hex_id))
    });
    let (status, algorithm) = classify_key(cert.public_key_info(), now);
    let selection = profile::select_for_cert(cert);
    let basic = cert.basic_constraints();
    CertificateInfo {
        subject: cert.subject().to_string(),
        issuer: cert.issuer().to_string(),
        serial: hex(cert.serial()),
        not_before: cert.not_before().to_string(),
        not_after: cert.not_after().to_string(),
        not_before_at: cert.not_before(),
        not_after_at: cert.not_after(),
        validity: super::validity(cert, now),
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
        sha256: hex(&Sha256::digest(cert.der())),
        private_key,
        friendly_name,
        local_key_id,
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

/// The terminal view: a section per aspect, every detail.
fn sections(report: &Report) -> Document {
    let mut doc = Document::default();
    if let Some(p12) = &report.pkcs12 {
        doc.section("PKCS#12");
        doc.field("encoding", p12.encoding);
        doc.field(
            "MAC",
            p12.mac.as_ref().map_or_else(
                || Line::status(Tone::Warn, "none"),
                |mac| Line::text(format!("{}, {} iterations", mac.digest, mac.iterations)),
            ),
        );
        doc.items("encryption", p12.encryption.iter().map(encryption_line));
        doc.items(
            "certificates",
            report
                .certificates
                .iter()
                .enumerate()
                .map(|(i, c)| bag_line(i, c)),
        );
        doc.items("keys", p12.keys.iter().map(key_line));
    }
    let count = report.certificates.len();
    for (i, cert) in report.certificates.iter().enumerate() {
        // The file is the user's own argument; a title only separates several certificates.
        if count > 1 {
            doc.title(format!("Certificate {} of {count}", i + 1));
        }
        name_section(&mut doc, "Subject", &cert.subject);
        name_section(&mut doc, "Issuer", &cert.issuer);
        // Issuer and serial identify the certificate; the hashes stay in JSON only.
        doc.field("serial", Line::code(&cert.serial));

        doc.section("Validity")
            .field("not before", when(cert.not_before_at))
            .field("not after", when(cert.not_after_at))
            .field("status", validity(cert, report.now));

        doc.section("TI").field(
            "type",
            cert.certificate_type
                .map_or_else(|| Line::dim("not detected"), Line::code),
        );
        if let Some(p) = &cert.profile {
            doc.field(
                "profile",
                Line::code(p.name).and_dim(format!(" ({})", p.detail)),
            );
        }
        if let Some(a) = &cert.admission {
            doc.field("admission", a.profession_items.join(", "));
            if let Some(number) = &a.registration_number {
                doc.field("registration", Line::code(number));
            }
            doc.items("profession", a.profession_oids.iter().map(oid_line));
        }
        doc.items("policies", cert.policies.iter().map(oid_line));

        let key_tone = match cert.key.status {
            s if s == KeyStatus::Admissible.as_str() => Tone::Good,
            s if s == KeyStatus::PhasedOut.as_str() => Tone::Warn,
            _ => Tone::Bad,
        };
        doc.section("Key").field(
            "algorithm",
            Line::text(format!("{} ", cert.key.algorithm)).and_status(key_tone, cert.key.status),
        );
        if cert.private_key {
            doc.field("private key", "in this file");
        }
        doc.field("signature", cert.signature_algorithm.as_str())
            .field("key usage", codes(&cert.key_usage))
            .field("ext. usage", codes(&cert.extended_key_usage))
            .field(
                "CA",
                match (cert.ca, cert.path_len) {
                    (true, Some(n)) => format!("yes, path length {n}"),
                    (true, None) => "yes".to_owned(),
                    (false, _) => "no".to_owned(),
                },
            )
            .field("critical", codes(&cert.critical_extensions));

        if !cert.ocsp_urls.is_empty() {
            doc.section("Revocation");
            for url in &cert.ocsp_urls {
                doc.field("OCSP", Line::link(url));
            }
        }
    }
    doc
}

fn encryption_line(e: &EncryptionInfo) -> Line {
    let line = Line::dim(format!("{}: ", e.target));
    // The PKCS#12 PBEs (RC2, 3DES) are what OpenSSL 3 only reads with -legacy.
    if e.algorithm.starts_with("PKCS#12") {
        line.and_status(Tone::Warn, &e.algorithm)
            .and_dim(" (legacy)")
    } else {
        line.and_text(&e.algorithm)
    }
}

fn bag_line(index: usize, cert: &CertificateInfo) -> Line {
    let (cn, _) = split_name(&cert.subject);
    let mut line = Line::text(format!("#{} ", index + 1)).and_strong(cn.unwrap_or(&cert.subject));
    if let Some(name) = &cert.friendly_name {
        line = line.and_dim(format!(" · name {name}"));
    }
    if let Some(id) = &cert.local_key_id {
        line = line.and_dim(" · key id ").and_code(id);
    }
    if cert.private_key {
        line = line.and_dim(" · with its key");
    }
    line
}

fn key_line(key: &P12KeyInfo) -> Line {
    let mut line = Line::text(key.curve.as_deref().map_or_else(
        || key.algorithm.clone(),
        |curve| format!("{} {curve}", key.algorithm),
    ));
    if let Some(name) = &key.friendly_name {
        line = line.and_dim(format!(" · name {name}"));
    }
    match key.certificate {
        Some(i) => line.and_dim(format!(" · for certificate #{}", i + 1)),
        None => line
            .and_text(" · ")
            .and_status(Tone::Warn, "no certificate"),
    }
}

/// A distinguished name as a section: the common name first and strong, the other
/// components on one line.
pub(super) fn name_section(doc: &mut Document, title: &str, name: &str) {
    let (cn, rest) = split_name(name);
    doc.section(title);
    if let Some(cn) = cn {
        doc.paragraph(Line::strong(cn));
    }
    if !rest.is_empty() {
        doc.paragraph(Line::dim(rest));
    }
}

/// The Markdown view: a summary, then one list, then the PEM.
fn summary(report: &Report) -> Document {
    let mut doc = Document::default();
    if let Some(p12) = &report.pkcs12 {
        let mut head = Line::strong("PKCS#12").and_text(format!(" · {}", p12.encoding));
        head = match &p12.mac {
            Some(mac) => head.and_dim(format!(" · MAC {} × {}", mac.digest, mac.iterations)),
            None => head.and_text(" · ").and_status(Tone::Warn, "no MAC"),
        };
        let mut encryption: Vec<&str> = Vec::new();
        for e in &p12.encryption {
            if !encryption.contains(&e.algorithm.as_str()) {
                encryption.push(&e.algorithm);
            }
        }
        if !encryption.is_empty() {
            head = head.and_dim(format!(" · {}", encryption.join(", ")));
        }
        doc.paragraph(head);
        doc.items("", p12.keys.iter().map(key_line));
    }
    let count = report.certificates.len();
    for (i, cert) in report.certificates.iter().enumerate() {
        // The file is the user's own argument; a title only separates several certificates.
        if count > 1 {
            doc.title(format!("Certificate {} of {count}", i + 1));
        }
        let (cn, rest) = split_name(&cert.subject);
        doc.paragraph(
            Line::strong(cn.unwrap_or("(no common name)"))
                .and_text(" · ")
                .and_line(
                    cert.certificate_type
                        .map_or_else(|| Line::dim("type not detected"), Line::code),
                )
                .and_text(" · ")
                .and_line(validity(cert, report.now)),
        );
        if !rest.is_empty() {
            doc.paragraph(Line::dim(rest));
        }
        let (issuer, _) = split_name(&cert.issuer);
        doc.paragraph(
            Line::text("issued by ")
                .and_text(issuer.unwrap_or(&cert.issuer))
                .and_dim(" · serial ")
                .and_code(&cert.serial),
        );

        doc.field(
            "valid",
            format!("{} → {}", when(cert.not_before_at), when(cert.not_after_at)),
        );
        if let Some(p) = &cert.profile {
            doc.field(
                "profile",
                Line::code(p.name).and_dim(format!(" ({})", p.detail)),
            );
        }
        if let Some(a) = &cert.admission {
            let mut line = Line::text(a.profession_items.join(", "));
            if let Some(number) = &a.registration_number {
                line = line.and_dim(" · registration ").and_code(number);
            }
            doc.field("admission", line);
            doc.items("profession", a.profession_oids.iter().map(oid_line));
        }
        doc.items("policies", cert.policies.iter().map(oid_line));
        let key_tone = match cert.key.status {
            s if s == KeyStatus::Admissible.as_str() => Tone::Good,
            s if s == KeyStatus::PhasedOut.as_str() => Tone::Warn,
            _ => Tone::Bad,
        };
        doc.field(
            "key",
            Line::text(format!("{} ", cert.key.algorithm))
                .and_status(key_tone, cert.key.status)
                .and_dim(format!(" · signed {}", cert.signature_algorithm)),
        );
        if cert.private_key {
            doc.field("private key", "in this file");
        }
        doc.field("key usage", codes(&cert.key_usage));
        if !cert.extended_key_usage.is_empty() {
            doc.field("ext. usage", codes(&cert.extended_key_usage));
        }
        if cert.ca {
            doc.field(
                "CA",
                cert.path_len
                    .map_or_else(|| "yes".to_owned(), |n| format!("yes, path length {n}")),
            );
        }
        if !cert.critical_extensions.is_empty() {
            doc.field("critical", codes(&cert.critical_extensions));
        }
        for url in &cert.ocsp_urls {
            doc.field("OCSP", Line::link(url));
        }
        doc.pem(&cert.pem);
    }
    doc
}

/// The common name of an RFC 4514 name, and its other components joined by ` · `.
pub(super) fn split_name(name: &str) -> (Option<&str>, String) {
    let mut cn = None;
    let mut rest = Vec::new();
    let mut start = 0;
    for part in dn_parts(name) {
        let len = part.len();
        let part = &name[start..start + len];
        start += len + 1;
        match part.strip_prefix("CN=") {
            Some(value) if cn.is_none() => cn = Some(value),
            _ => rest.push(part),
        }
    }
    (cn, rest.join(" · "))
}

/// The components of an RFC 4514 name; a comma escaped with a backslash is part of its
/// value.
fn dn_parts(name: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut escaped = false;
    for c in name.chars() {
        match (escaped, c) {
            (true, _) => {
                current.push(c);
                escaped = false;
            }
            (false, '\\') => {
                current.push(c);
                escaped = true;
            }
            (false, ',') => parts.push(core::mem::take(&mut current)),
            (false, _) => current.push(c),
        }
    }
    if !current.is_empty() {
        parts.push(current);
    }
    parts
}

fn validity(cert: &CertificateInfo, now: Timestamp) -> Line {
    match cert.validity {
        "valid" => Line::status(Tone::Good, "valid").and_text(format!(
            ", {} left",
            span(cert.not_after_at.0.saturating_sub(now.0))
        )),
        "expired" => Line::status(Tone::Bad, "expired").and_text(format!(
            " {} ago",
            span(now.0.saturating_sub(cert.not_after_at.0))
        )),
        _ => Line::status(Tone::Bad, "not yet valid").and_text(format!(
            ", starts in {}",
            span(cert.not_before_at.0.saturating_sub(now.0))
        )),
    }
}

fn oid_line(o: &OidInfo) -> Line {
    let line = Line::code(&o.oid);
    match o.name {
        Some(name) => line.and_dim(format!(" {name}")),
        None => line,
    }
}

/// Values as a comma-separated list of code spans; `none` for no values.
fn codes<T: AsRef<str>>(values: &[T]) -> Line {
    let mut line = Line::default();
    for (i, value) in values.iter().enumerate() {
        if i > 0 {
            line = line.and_text(", ");
        }
        line = line.and_code(value.as_ref());
    }
    if line.0.is_empty() {
        Line::dim("none")
    } else {
        line
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distinguished_names_split_on_unescaped_commas() {
        assert_eq!(
            dn_parts(r"CN=Praxis Dr. A\, B,O=X,C=DE"),
            [r"CN=Praxis Dr. A\, B", "O=X", "C=DE"]
        );
        assert_eq!(dn_parts(""), Vec::<String>::new());
    }
}
