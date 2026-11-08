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

//! `ti pki inspect`: what the TI reads from a certificate, without validating it.

use std::path::Path;

use serde::Serialize;
use ti_client::pki::inspect::{
    self as engine, CertificateInfo, EncryptionInfo, Inspection, P12KeyInfo, Pkcs12Info,
};
use ti_pki::key::KeyStatus;
use ti_pki::{Env, Timestamp};

use crate::cli::GlobalArgs;
use crate::error::{CliError, Exit};
use crate::input;
use crate::output::document::{TreeRow, date, span, when};
use crate::output::{Document, Line, Oid, Output, SCHEMA, Tone};

/// The JSON document.
#[derive(Serialize)]
struct Report {
    schema: u32,
    #[serde(flatten)]
    inspection: Inspection,
    /// The instant validity was judged at, for the remaining-time text.
    #[serde(skip)]
    now: Timestamp,
    /// Per certificate, the path to a trusted root as the trust material suggests it,
    /// not validated; for the views only.
    #[serde(skip)]
    trees: Vec<Vec<TreeRow>>,
}

impl core::ops::Deref for Report {
    type Target = Inspection;

    fn deref(&self) -> &Inspection {
        &self.inspection
    }
}

pub fn run(
    file: &Path,
    p12_password: &str,
    short: bool,
    global: &GlobalArgs,
    out: &Output,
) -> Result<Exit, CliError> {
    let source = input::read(file)?;
    let now = Timestamp::now();
    let (inspection, certs) = engine::inspect(&source.bytes, &source.name, p12_password, now)?;
    let trees = if out.is_json() || short {
        Vec::new()
    } else {
        trees(&certs, global, out, now)
    };
    let report = Report {
        inspection,
        schema: SCHEMA,
        now,
        trees,
    };
    if out.is_json() {
        out.json(&report)?;
    } else if short {
        let table = short_table(&report);
        out.render_views(&table, &table)?;
    } else {
        out.render_views(&sections(&report), &summary(&report))?;
    }
    Ok(Exit::Ok)
}

/// `--short`: a row per certificate. The Telematik-ID is the admission's registration
/// number; CAs never carry one, so its column appears only when a certificate does.
fn short_table(report: &Report) -> Document {
    let telematik_id = |cert: &CertificateInfo| {
        cert.admission
            .as_ref()
            .and_then(|a| a.registration_number.clone())
    };
    let with_id = report
        .certificates
        .iter()
        .any(|c| telematik_id(c).is_some());
    let rows = report
        .certificates
        .iter()
        .map(|cert| {
            let (cn, _) = split_name(&cert.subject);
            let mut row = vec![
                Line::strong(cn.unwrap_or_else(|| cert.subject.clone())),
                Line::text(date(cert.not_after_at)),
            ];
            if with_id {
                row.push(telematik_id(cert).map_or_else(|| Line::dim("-"), Line::code));
            }
            row
        })
        .collect();
    let headers: &[&str] = if with_id {
        &["SUBJECT", "NOT AFTER", "TELEMATIK-ID"]
    } else {
        &["SUBJECT", "NOT AFTER"]
    };
    let mut doc = Document::default();
    doc.table(headers, rows);
    doc
}

/// Shows `certificates` as `pki inspect` does, `source` naming where they came from:
/// `connector describe certificate`, whose JSON is therefore `pki inspect`'s.
pub fn show(
    source: String,
    certificates: Vec<ti_pki::Certificate>,
    global: &GlobalArgs,
    out: &Output,
) -> Result<Exit, CliError> {
    let now = Timestamp::now();
    let trees = if out.is_json() {
        Vec::new()
    } else {
        trees(&certificates, global, out, now)
    };
    let report = Report {
        schema: SCHEMA,
        inspection: engine::describe_all(source, certificates, now),
        now,
        trees,
    };
    if out.is_json() {
        out.json(&report)?;
    } else {
        out.render_views(&sections(&report), &summary(&report))?;
    }
    Ok(Exit::Ok)
}

/// For each of `certs`, the path to a trusted root as the trust material suggests it
/// ([`engine::paths`]), as a tree. Without a cached TSL an issuer that is missing is
/// reported as not loaded, not as untrusted.
fn trees(
    certs: &[ti_pki::Certificate],
    global: &GlobalArgs,
    out: &Output,
    now: Timestamp,
) -> Vec<Vec<TreeRow>> {
    let client = crate::http::client(&global.net, out.verbosity());
    let dirs = crate::profile::Profile::resolve(global)
        .ok()
        .map(|profile| profile.dirs());
    let paths = engine::paths(&client, dirs.as_ref(), certs, now, crate::trust::warn);
    paths
        .chains
        .iter()
        .map(|(chain, complete)| {
            let mut rows = super::chain_tree(
                chain,
                *complete,
                now,
                |_| Line::default(),
                |_| Line::default(),
            );
            if !complete
                && !paths.tsl_loaded
                && let Some(missing) = rows.last_mut()
            {
                missing.detail = tsl_not_loaded(paths.env);
            }
            rows
        })
        .collect()
}

/// The missing issuer's note when no TSL is cached: its CAs may well be trusted, and the
/// command that loads them.
fn tsl_not_loaded(env: Option<Env>) -> Line {
    let fetch = match env {
        Some(env) => format!("ti pki tsl show --env {}", env.as_str()),
        None => "ti pki tsl show --env ENV".to_owned(),
    };
    Line::status(Tone::Warn, "TSL not loaded, its CAs unknown; ").and_code(fetch)
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
        certificate_sections(&mut doc, cert, report.now);
        doc.section("Trust (not validated)");
        if let Some(rows) = report.trees.get(i) {
            doc.tree(rows.clone());
        }
    }
    doc
}

/// The sections that describe one certificate, as `pki inspect` and `pki verify` show
/// them: subject, issuer, validity at `now`, what the TI reads, key, revocation sources.
pub(super) fn certificate_sections(doc: &mut Document, cert: &CertificateInfo, now: Timestamp) {
    name_section(doc, "Subject", &cert.subject);
    alt_names(doc, &cert.subject_alt_names);
    name_section(doc, "Issuer", &cert.issuer);
    // Issuer and serial identify the certificate; the hashes stay in JSON only.
    doc.field("serial", Line::code(&cert.serial));

    doc.section("Validity")
        .field("not before", when(cert.not_before_at))
        .field("not after", when(cert.not_after_at))
        .field("status", validity(cert, now));

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

/// The subject alternative names, one per line; `none` without any.
fn alt_names(doc: &mut Document, names: &[String]) {
    if names.is_empty() {
        doc.field("alt. names", Line::dim("none"));
    } else {
        doc.items("alt. names", names.iter().map(Line::code));
    }
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
    let mut line = Line::text(format!("#{} ", index + 1))
        .and_strong(cn.unwrap_or_else(|| cert.subject.clone()));
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

/// A distinguished name as a section, one field per component in the name's order:
/// `common name`, `organization` and so on; the common name strong.
pub(super) fn name_section(doc: &mut Document, title: &str, name: &str) {
    doc.section(title);
    for part in dn_parts(name) {
        let (key, value) = part.split_once('=').unwrap_or(("", part.as_str()));
        let value = unescape(value);
        let line = if key == "CN" {
            Line::strong(value)
        } else {
            Line::text(value)
        };
        doc.field(attribute_label(key), line);
    }
}

/// The label of a name component: its attribute in words, else the attribute as
/// written.
fn attribute_label(key: &str) -> &str {
    // x509-cert prints the attributes RFC 4514 has no short name for in upper case
    // (SERIALNUMBER, TITLE) and unknown ones as dotted OIDs.
    match key {
        "CN" => "common name",
        "GN" | "givenName" => "given name",
        "SN" | "surname" => "surname",
        "O" => "organization",
        "OU" => "org. unit",
        "C" => "country",
        "L" => "locality",
        "ST" => "state",
        "STREET" | "street" => "street",
        "POSTALCODE" | "postalCode" | "2.5.4.17" => "postal code",
        "TITLE" | "title" | "2.5.4.12" => "title",
        "serialNumber" | "SERIALNUMBER" | "2.5.4.5" => "serialNumber",
        "2.5.4.97" => "org. id",
        "EMAIL" | "emailAddress" => "email",
        "PSEUDONYM" | "2.5.4.65" => "pseudonym",
        "INITIALS" | "2.5.4.43" => "initials",
        "DESCRIPTION" | "2.5.4.13" => "description",
        "DNQUALIFIER" | "2.5.4.46" => "dn qualifier",
        "UID" => "user id",
        "DC" => "domain",
        other => other,
    }
}

/// The PKCS#12 container in one line, then its keys.
fn p12_summary(doc: &mut Document, p12: &Pkcs12Info) {
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

/// The Markdown view: a summary, then one list, then the PEM.
fn summary(report: &Report) -> Document {
    let mut doc = Document::default();
    if let Some(p12) = &report.pkcs12 {
        p12_summary(&mut doc, p12);
    }
    let count = report.certificates.len();
    for (i, cert) in report.certificates.iter().enumerate() {
        // The file is the user's own argument; a title only separates several certificates.
        if count > 1 {
            doc.title(format!("Certificate {} of {count}", i + 1));
        }
        let (cn, rest) = split_name(&cert.subject);
        doc.paragraph(
            Line::strong(cn.unwrap_or_else(|| "(no name)".to_owned()))
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
                .and_text(issuer.unwrap_or_else(|| cert.issuer.clone()))
                .and_dim(" · serial ")
                .and_code(&cert.serial),
        );
        alt_names(&mut doc, &cert.subject_alt_names);

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
        if let Some(rows) = report.trees.get(i) {
            doc.tree(rows.clone());
        }
        doc.pem(&cert.pem);
    }
    doc
}

/// The name to show for an RFC 4514 name: its common name, else `given name surname`
/// (from `GN`/`SN`), and the other components joined by ` · `.
pub(super) fn split_name(name: &str) -> (Option<String>, String) {
    let mut cn = None;
    let (mut given, mut surname) = (None, None);
    let mut rest = Vec::new();
    for part in dn_parts(name) {
        let (key, value) = part.split_once('=').unwrap_or(("", part.as_str()));
        let value = unescape(value);
        match key {
            "CN" if cn.is_none() => {
                cn = Some(value);
                continue;
            }
            "GN" | "givenName" if given.is_none() => given = Some(value.clone()),
            "SN" | "surname" if surname.is_none() => surname = Some(value.clone()),
            _ => {}
        }
        rest.push(format!("{key}={value}"));
    }
    let person = match (given, surname) {
        (Some(given), Some(surname)) => Some(format!("{given} {surname}")),
        (given, surname) => given.or(surname),
    };
    (cn.or(person), rest.join(" · "))
}

/// The attribute=value components of an RFC 4514 §3 name in its order, the values of a
/// multi-valued RDN (`GN=…+SN=…+CN=…`, as on an HBA) one by one; an escaped `,` or `+`
/// is part of its value.
pub(super) fn dn_parts(name: &str) -> Vec<String> {
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
            (false, ',' | '+') => parts.push(core::mem::take(&mut current)),
            (false, _) => current.push(c),
        }
    }
    if !current.is_empty() {
        parts.push(current);
    }
    parts
}

/// An RFC 4514 §3 attribute value as text: `\,` becomes `,`, `\C3\A4` the UTF-8 it
/// encodes, and a `#`-hex DER string (an attribute without a short name, such as
/// organizationIdentifier) its text.
pub(super) fn unescape(value: &str) -> String {
    if let Some(text) = value.strip_prefix('#').and_then(der_string) {
        return text;
    }
    let mut bytes = Vec::with_capacity(value.len());
    let mut rest = value.as_bytes();
    while let Some((&b, tail)) = rest.split_first() {
        rest = tail;
        if b != b'\\' {
            bytes.push(b);
            continue;
        }
        // Two hex digits exactly: from_str_radix would also take a sign, as in `\+C`.
        let hex = rest
            .get(..2)
            .filter(|h| h.iter().all(u8::is_ascii_hexdigit))
            .and_then(|h| std::str::from_utf8(h).ok())
            .and_then(|h| u8::from_str_radix(h, 16).ok());
        if let Some(byte) = hex {
            bytes.push(byte);
            rest = &rest[2..];
        } else if let Some((&next, tail)) = rest.split_first() {
            bytes.push(next);
            rest = tail;
        }
    }
    String::from_utf8_lossy(&bytes).into_owned()
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

fn oid_line(o: &Oid) -> Line {
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

/// The text of a hex-encoded DER UTF8String, PrintableString, TeletexString or
/// IA5String with a short-form length; `None` for anything else, which is then shown as
/// written.
fn der_string(hex: &str) -> Option<String> {
    if !hex.len().is_multiple_of(2) || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect::<Option<_>>()?;
    let (&[tag, len], content) = bytes.split_first_chunk::<2>()?;
    let string_tag = matches!(tag, 0x0c | 0x13 | 0x14 | 0x16);
    if !string_tag || len >= 0x80 || usize::from(len) != content.len() {
        return None;
    }
    String::from_utf8(content.to_vec()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc_4514_3_distinguished_names_split_on_unescaped_commas_and_pluses() {
        assert_eq!(
            dn_parts(r"CN=Praxis Dr. A\, B,O=X,C=DE"),
            [r"CN=Praxis Dr. A\, B", "O=X", "C=DE"]
        );
        assert_eq!(
            dn_parts(r"GN=Ullrich+SN=A\+B+CN=Ullrich A,C=DE"),
            ["GN=Ullrich", r"SN=A\+B", "CN=Ullrich A", "C=DE"]
        );
        assert_eq!(dn_parts(""), Vec::<String>::new());
    }

    #[test]
    fn the_common_name_of_a_multi_valued_rdn() {
        let (cn, rest) = split_name(
            "GN=Ullrich+SN=Angermänn+SERIALNUMBER=80276883110000129084+CN=Ullrich AngermännTEST-ONLY,C=DE",
        );
        assert_eq!(cn.as_deref(), Some("Ullrich AngermännTEST-ONLY"));
        assert_eq!(
            rest,
            "GN=Ullrich · SN=Angermänn · SERIALNUMBER=80276883110000129084 · C=DE"
        );
    }

    #[test]
    fn without_a_common_name_the_given_name_and_surname() {
        let (name, _) = split_name("GN=Erika+SN=Mustermann+SERIALNUMBER=1,C=DE");
        assert_eq!(name.as_deref(), Some("Erika Mustermann"));
        assert_eq!(split_name("O=X,C=DE").0, None);
    }

    #[test]
    fn rfc_4514_3_escaped_values() {
        assert_eq!(unescape(r"A\, B\+C"), "A, B+C");
        assert_eq!(unescape(r"Angerm\C3\A4nn"), "Angermänn");
        assert_eq!(unescape(r"trailing\"), "trailing");
        assert_eq!(unescape("#0c0756415444452d31"), "VATDE-1");
        assert_eq!(unescape("#300100"), "#300100");
        assert_eq!(unescape("#0c05ab"), "#0c05ab");
    }
}
