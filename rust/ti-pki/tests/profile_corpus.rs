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

//! `spec/pki-profiles/testdata`: what this crate says of certificate types, admission and
//! profiles, the corpus `go/tipki` is held to. Set `TI_PKI_BLESS=1` to write it again after a
//! deliberate change to a rule; otherwise a difference fails here and the Go side is never asked.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde_json::{Value, json};
use ti_pki::admission::AdmissionStatement;
use ti_pki::cert_type::CertificateType;
use ti_pki::checks::{key_usage_name, role_oid};
use ti_pki::profile::{PROFILES, select_for_cert};
use ti_pki::revocation::RevocationMode;
use ti_pki::{Certificate, TrustConfig, TrustStore, Validator, detect_certificate_type};

fn testdata() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../spec/pki-profiles/testdata")
}

fn strings<T: ToString>(items: impl IntoIterator<Item = T>) -> Vec<String> {
    items.into_iter().map(|item| item.to_string()).collect()
}

fn mode(mode: RevocationMode) -> &'static str {
    match mode {
        RevocationMode::HardFail => "hard-fail",
        RevocationMode::SoftFail => "soft-fail",
        RevocationMode::Disabled => "disabled",
    }
}

fn tables() -> Value {
    let types: Vec<Value> = CertificateType::ALL
        .iter()
        .map(|t| {
            let spec = t.spec();
            json!({
                "name": t.as_str(),
                "oid": t.oid().to_string(),
                "key_usage": spec.key_usage.iter().map(|bit| key_usage_name(*bit)).collect::<Vec<_>>(),
                "ext_key_usage": strings(spec.ext_key_usage),
                "policies": strings(spec.policies),
                "role_oids": strings(spec.role_oids),
            })
        })
        .collect();
    let profiles: Vec<Value> = PROFILES
        .iter()
        .map(|p| {
            json!({
                "name": p.name,
                "description": p.description,
                "revocation": mode(p.revocation),
                "required_role_oids": strings(p.required_role_oids),
                "accepts_types": strings(p.accepts_types),
                "default_for": strings(p.default_for),
            })
        })
        .collect();
    let oids: Vec<Value> = ti_pki::oid::all()
        .iter()
        .map(|info| {
            json!({
                "oid": info.oid.to_string(),
                "reference": info.reference,
                "description": info.description,
                "document": info.document,
                "certificate_types": info.certificate_types,
            })
        })
        .collect();
    json!({
        "types": types,
        "profiles": profiles,
        "oids": oids,
        "professions": strings(ti_pki::oid::PROFESSIONS),
        "institutions": strings(ti_pki::oid::INSTITUTIONS),
        "error_codes": strings(ti_pki::ErrorCode::ALL),
    })
}

fn findings(cert: &Certificate, t: CertificateType) -> BTreeMap<&'static str, Vec<String>> {
    let config = TrustConfig::for_anchor(Vec::new());
    PROFILES
        .iter()
        .map(|p| {
            let validator =
                Validator::new(&config, Arc::new(TrustStore::new([]))).with_type_baseline(t);
            let mut checks = validator.ee_checks();
            checks.push(role_oid(p.effective_role_oids(t)));
            let codes = checks
                .iter()
                .filter_map(|check| check(cert).err())
                .map(|e| e.code.to_string())
                .collect();
            (p.name, codes)
        })
        .collect()
}

fn certificate(name: &str, cert: &Certificate) -> Value {
    let cert_type = detect_certificate_type(cert);
    let selection = select_for_cert(cert);
    let admission = match cert.admission() {
        Ok(Some(a)) => json!({
            "items": a.profession_items,
            "oids": strings(&a.profession_oids),
            "registration_number": a.registration_number,
        }),
        Ok(None) => Value::Null,
        Err(_) => json!("malformed"),
    };
    json!({
        "file": name,
        "type": cert_type.map(CertificateType::as_str),
        "admission": admission,
        "selection": {
            "profile": selection.profile.map(|p| p.name),
            "reason": selection.reason.as_str(),
            "candidates": selection.candidates.iter().map(|p| p.name).collect::<Vec<_>>(),
        },
        "findings": cert_type.map(|t| findings(cert, t)),
    })
}

fn certificates() -> Value {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/pki/types");
    let mut names: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .filter(|name| Path::new(name).extension().is_some_and(|e| e == "pem"))
        .collect();
    names.sort();
    Value::Array(
        names
            .iter()
            .map(|name| {
                let pem = std::fs::read(dir.join(name)).unwrap();
                certificate(name, &ti_pki::parse_pem_certificates(&pem).unwrap()[0])
            })
            .collect(),
    )
}

/// PROF-001, 002, 003, 020, 030: the corpus is what this crate says.
#[test]
fn prof_030_the_corpus_is_what_ti_pki_says() {
    let corpus = json!({ "tables": tables(), "certificates": certificates() });
    let path = testdata().join("corpus.json");
    let written = serde_json::to_string_pretty(&corpus).unwrap() + "\n";
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

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

/// PROF-010, 011: hand-built values, the malformed ones above all, on which Go must agree.
#[test]
fn prof_010_admission_values_are_read_or_refused_as_stated() {
    let vectors: Value =
        serde_json::from_slice(&std::fs::read(testdata().join("admission.json")).unwrap()).unwrap();
    for vector in vectors.as_array().unwrap() {
        let name = vector["name"].as_str().unwrap();
        let parsed = AdmissionStatement::from_der(&hex(vector["der"].as_str().unwrap()));
        assert_eq!(
            vector["accept"].as_bool().unwrap(),
            parsed.is_ok(),
            "{name}: {parsed:?}"
        );
        if let Ok(statement) = parsed {
            assert_eq!(vector["items"], json!(statement.profession_items), "{name}");
            assert_eq!(
                vector["oids"],
                json!(strings(&statement.profession_oids)),
                "{name}"
            );
            assert_eq!(
                vector["registration_number"],
                json!(statement.registration_number),
                "{name}"
            );
        }
    }
}
