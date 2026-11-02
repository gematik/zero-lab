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

//! `spec/pki-path/testdata/tsl.json`: what this crate reads from the published lists, and which of
//! their CAs it keeps, the corpus `go/tipki` is held to. Set `TI_PKI_BLESS=1` to write it again after a
//! deliberate change to a rule.
#![cfg(all(feature = "brainpool", feature = "rsa", feature = "dangerous-nonprod"))]

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use ti_pki::tsl::{SchemeInfo, Tsl, match_to_roots};
use ti_pki::tsl_signature::{Sequence, TslState, VerifiedTsl};
use ti_pki::{Certificate, Env, Tier, Timestamp, TrustConfig, TrustStore, roots};

const CAPTURED: &str = "2026-11-01T16:47:42Z";

fn testdata() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../spec")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

fn fingerprint(cert: &Certificate) -> String {
    hex(&Sha256::digest(cert.der()))
}

fn lines_digest(lines: &[String]) -> String {
    hex(&Sha256::digest(lines.join("\n").as_bytes()))
}

fn scheme_lines(scheme: &SchemeInfo) -> Vec<String> {
    let mut lines = vec![format!(
        "{}|{}|{}|{}",
        scheme.version_identifier.unwrap_or(0),
        scheme.tsl_type,
        scheme.scheme_name,
        scheme.operator_name
    )];
    lines.extend(scheme.postal_addresses.iter().map(|a| {
        format!(
            "{}|{}|{}|{}|{}",
            a.street, a.postal_code, a.locality, a.state, a.country
        )
    }));
    lines.push(scheme.electronic_addresses.join(","));
    lines.extend(
        scheme
            .pointers
            .iter()
            .map(|p| format!("{}|{}", p.location, p.additional_information.join(","))),
    );
    lines
}

fn sequence_cases(verified: &VerifiedTsl) -> Vec<Value> {
    let tsl = &verified.tsl;
    let number = tsl.sequence_number;
    [
        ("", 0),
        (tsl.id.as_str(), number),
        ("another", number - 1),
        ("another", number),
        ("another", number + 1),
        (tsl.id.as_str(), number - 1),
        (tsl.id.as_str(), number + 1),
    ]
    .iter()
    .map(|(id, stored)| {
        let state = TslState {
            id: (*id).to_owned(),
            sequence_number: *stored,
        };
        let result = match verified.check_sequence((!id.is_empty()).then_some(&state)) {
            Ok(Sequence::Newer) => "newer".to_owned(),
            Ok(Sequence::Same) => "same".to_owned(),
            Ok(_) => "other".to_owned(),
            Err(e) => e.code.to_string(),
        };
        json!({ "id": id, "number": stored, "result": result })
    })
    .collect()
}

fn summary(name: &str, stem: &str, env: Env) -> Value {
    let now = Timestamp::parse_rfc3339(CAPTURED).unwrap();
    let dir = testdata().join("tsl-detached/testdata");
    let read = |suffix: &str| std::fs::read(dir.join(format!("{stem}.{suffix}"))).unwrap();
    let config = TrustConfig::preset(env);
    let verified = Tsl::parse_verified(&read("xml"), &read("sig"), &config, now).unwrap();
    let tsl = &verified.tsl;
    let services: Vec<String> = tsl
        .services
        .iter()
        .map(|s| {
            format!(
                "{}|{}|{}|{}|{}|{}|{}|{}",
                s.provider,
                s.name,
                s.service_type,
                s.status,
                s.status_starting_time.map_or(0, |t| t.0),
                s.certificate.as_ref().map(fingerprint).unwrap_or_default(),
                s.supply_points.join(","),
                s.type_oids
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(","),
            )
        })
        .collect();
    let scheme = &tsl.scheme;
    let scheme_lines = scheme_lines(scheme);
    let sequence = sequence_cases(&verified);
    let candidates = tsl.intermediate_cas();
    let intermediates: Vec<String> = candidates
        .iter()
        .map(|c| {
            format!(
                "{}|{}|{}",
                fingerprint(&c.certificate),
                c.provider,
                c.revoked_since.map_or(0, |t| t.0)
            )
        })
        .collect();
    let walked = roots::load(&config, now).unwrap();
    let store = TrustStore::new(walked.trusted.iter().cloned());
    let matched = match_to_roots(candidates, &store, &config.algorithms);
    let kept: Vec<Value> = matched
        .intermediates
        .iter()
        .map(|i| {
            json!({
                "sha256": fingerprint(&i.certificate),
                "signature": i.certificate.inner().signature_algorithm().oid.to_string(),
            })
        })
        .collect();
    let rejected: Vec<Value> = matched
        .rejected
        .iter()
        .map(|(i, reason)| json!({ "sha256": fingerprint(&i.certificate), "reason": reason.to_string() }))
        .collect();
    json!({
        "name": name,
        "stem": stem,
        "nonprod": env != Env::Prod,
        "production": verified.tier == Tier::Prod,
        "scheme_sha256": lines_digest(&scheme_lines),
        "primary": scheme.primary_location().unwrap_or_default(),
        "backup": scheme.backup_location().unwrap_or_default(),
        "sequence": sequence,
        "id": tsl.id,
        "sequence_number": tsl.sequence_number,
        "issued_at": tsl.issued_at.0,
        "next_update": tsl.next_update.map(|t| t.0),
        "services": tsl.services.len(),
        "services_sha256": lines_digest(&services),
        "skipped": tsl.skipped.len(),
        "intermediates": intermediates.len(),
        "intermediates_sha256": lines_digest(&intermediates),
        "kept": kept,
        "rejected": rejected,
    })
}

/// BUNDLE-003, with the rules of `spec/tsl-detached` on what a list holds.
#[test]
fn tsl_001_the_corpus_is_what_ti_pki_says() {
    let corpus = json!({
        "captured": CAPTURED,
        "lists": [
            summary("prod", "prod/ECC-RSA_TSL", Env::Prod),
            summary("ref", "ref/ECC-RSA_TSL-ref", Env::Ref),
            summary("test", "test/ECC-RSA_TSL-test", Env::Test),
        ],
    });
    let written = serde_json::to_string_pretty(&corpus).unwrap() + "\n";
    let path = testdata().join("pki-path/testdata/tsl.json");
    if std::env::var_os("TI_PKI_BLESS").is_some() {
        std::fs::write(&path, written).unwrap();
        return;
    }
    let stored = std::fs::read_to_string(&path).expect("TI_PKI_BLESS=1 writes the corpus");
    assert_eq!(
        stored, written,
        "the corpus differs: TI_PKI_BLESS=1 after a deliberate change"
    );
}
