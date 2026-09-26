//! `tir pki inspect`: what the TI reads from a certificate, without validating it.

use std::path::Path;

use serde::Serialize;
use sha2::{Digest, Sha256};
use ti_pki::key::{KeyStatus, classify_key};
use ti_pki::load::SystemClock;
use ti_pki::{
    Certificate, CertificateType, Clock, Timestamp, checks, detect_certificate_type, profile,
};
use x509_cert::der::oid::ObjectIdentifier;

use crate::error::{CliError, Exit};
use crate::input;
use crate::output::document::{span, when};
use crate::output::{Document, Line, OidInfo, Output, SCHEMA, Tone, hex};

/// The JSON document.
#[derive(Serialize)]
struct Report {
    schema: u32,
    source: String,
    certificates: Vec<CertificateInfo>,
    /// The instant validity was judged at, for the remaining-time text.
    #[serde(skip)]
    now: Timestamp,
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

pub fn run(file: &Path, out: &Output) -> Result<Exit, CliError> {
    let source = input::read(file)?;
    let certs = input::certificates(&source)?;
    let now = SystemClock.now();
    let report = Report {
        schema: SCHEMA,
        source: source.name,
        certificates: certs.iter().map(|cert| describe(cert, now)).collect(),
        now,
    };
    if out.is_json() {
        out.json(&report)?;
    } else {
        out.render(&document(&report))?;
    }
    Ok(Exit::Ok)
}

fn describe(cert: &Certificate, now: Timestamp) -> CertificateInfo {
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
        validity: if now < cert.not_before() {
            "not_yet_valid"
        } else if now > cert.not_after() {
            "expired"
        } else {
            "valid"
        },
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

fn document(report: &Report) -> Document {
    let mut doc = Document::default();
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
        // Fields first, lists after, so Markdown gets one table per section.
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
        doc.section("Key")
            .field(
                "algorithm",
                Line::text(format!("{} ", cert.key.algorithm))
                    .and_status(key_tone, cert.key.status),
            )
            .field("signature", cert.signature_algorithm.as_str())
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

/// A distinguished name as a section: the common name first and strong, the other
/// components on one line.
fn name_section(doc: &mut Document, title: &str, name: &str) {
    let parts = dn_parts(name);
    let (cn, rest): (Vec<&str>, Vec<&str>) = parts
        .iter()
        .map(String::as_str)
        .partition(|part| part.starts_with("CN="));
    doc.section(title);
    if let Some(cn) = cn.first() {
        doc.paragraph(Line::strong(&cn[3..]));
    }
    if !rest.is_empty() {
        doc.paragraph(Line::dim(rest.join(" · ")));
    }
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
