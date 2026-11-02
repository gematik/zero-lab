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

//! `spec/pki-path/testdata`: what this crate says of chains and bundles, the corpus `go/tipki` is
//! held to. Set `TI_PKI_BLESS=1` to write `path.json` again after a deliberate change to a rule.
#![cfg(feature = "brainpool")]

use core::time::Duration;
use std::path::{Path, PathBuf};

use serde_json::{Value, json};
use ti_pki::load::Bundle;
use ti_pki::path::ValidityModel;
use ti_pki::{
    Certificate, PathOptions, Timestamp, TrustStore, algorithms, build_chain, validate_path,
};

/// `TestPki::NOW`: every fixture's validity is fixed around it.
const NOW: u64 = 1_767_225_600;
const TEN_YEARS: u64 = 10 * 366 * 86_400;

fn testdata() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../spec/pki-path/testdata")
}

/// Every fixture but the OCSP responders', which no chain here reaches.
fn fixtures() -> Vec<(String, Certificate)> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/pki");
    let mut names: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .filter(|name| {
            Path::new(name).extension().is_some_and(|e| e == "pem") && !name.starts_with("ocsp-")
        })
        .collect();
    names.sort();
    names
        .into_iter()
        .map(|name| {
            let pem = std::fs::read(dir.join(&name)).unwrap();
            let cert = ti_pki::parse_pem_certificates(&pem).unwrap().remove(0);
            (name, cert)
        })
        .collect()
}

fn tampered(cert: &Certificate) -> Certificate {
    let mut der = cert.der().to_vec();
    *der.last_mut().unwrap() ^= 1;
    Certificate::from_der(&der).unwrap()
}

fn case(
    name: &str,
    leaf: &Certificate,
    intermediates: &[Certificate],
    store: &TrustStore,
    now: u64,
    model: ValidityModel,
    names: &dyn Fn(&Certificate) -> String,
) -> Value {
    let (chain, incomplete) = match build_chain(leaf, intermediates, store) {
        Ok(chain) => (chain, false),
        Err(e) => (e.partial, true),
    };
    let listed: Vec<String> = chain.iter().map(names).collect();
    let (errors, warnings) = if incomplete {
        (Vec::new(), Vec::new())
    } else {
        let result = validate_path(
            &chain,
            &PathOptions {
                now: Timestamp(now),
                algorithms: algorithms::DEFAULT,
                max_clock_skew: Duration::ZERO,
                ee_checks: &[],
                model,
            },
        )
        .unwrap();
        (
            result
                .errors
                .iter()
                .map(|e| json!([e.code.to_string(), e.subject]))
                .collect(),
            result
                .warnings
                .iter()
                .map(|w| json!([w.code.to_string(), w.subject]))
                .collect(),
        )
    };
    json!({
        "name": name,
        "now": now,
        "compromise": model == ValidityModel::Compromise,
        "chain": listed,
        "incomplete": incomplete,
        "errors": errors,
        "warnings": warnings,
    })
}

fn matrix() -> Value {
    let all = fixtures();
    let is_root = |name: &str| matches!(name, "rca1.pem" | "rca7.pem" | "rca-rsa.pem");
    let store = TrustStore::new(
        all.iter()
            .filter(|(n, _)| is_root(n))
            .map(|(_, c)| c.clone()),
    );
    let mut cases = Vec::new();
    for (name, leaf) in all.iter().filter(|(n, _)| !is_root(n)) {
        let intermediates: Vec<Certificate> = all
            .iter()
            .filter(|(n, _)| !is_root(n) && n != name)
            .map(|(_, c)| c.clone())
            .collect();
        let names = |cert: &Certificate| -> String {
            all.iter()
                .find(|(_, c)| c == cert)
                .map_or_else(|| "tampered".to_owned(), |(n, _)| n.clone())
        };
        for now in [NOW, NOW - TEN_YEARS, NOW + TEN_YEARS] {
            for model in [ValidityModel::Shell, ValidityModel::Compromise] {
                cases.push(case(name, leaf, &intermediates, &store, now, model, &names));
            }
        }
        cases.push(case(
            &format!("tampered:{name}"),
            &tampered(leaf),
            &intermediates,
            &store,
            NOW,
            ValidityModel::Shell,
            &names,
        ));
    }
    Value::Array(cases)
}

/// PATH-001 to PATH-006: the corpus is what this crate says.
#[test]
fn path_001_the_corpus_is_what_ti_pki_says() {
    let written = serde_json::to_string_pretty(&matrix()).unwrap() + "\n";
    let path = testdata().join("path.json");
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

/// BUNDLE-001: what ti-pki reads or refuses, on which `go/tipki` must agree.
#[test]
fn bundle_001_values_are_read_or_refused_as_stated() {
    use base64ct::{Base64, Encoding};
    let vectors: Value =
        serde_json::from_slice(&std::fs::read(testdata().join("bundle.json")).unwrap()).unwrap();
    for vector in vectors.as_array().unwrap() {
        let name = vector["name"].as_str().unwrap();
        let parsed = Bundle::from_slice(vector["json"].as_str().unwrap().as_bytes());
        assert_eq!(
            vector["accept"].as_bool().unwrap(),
            parsed.is_ok(),
            "{name}: {parsed:?}"
        );
        let Ok(bundle) = parsed else { continue };
        let b64 = |bytes: &[u8]| Base64::encode_string(bytes);
        assert_eq!(vector["roots"], b64(&bundle.material.roots), "{name}");
        assert_eq!(vector["tsl"], b64(&bundle.material.tsl), "{name}");
        assert_eq!(vector["fetched_at"], bundle.material.fetched_at.0, "{name}");
        let detached = bundle.material.detached.unwrap();
        assert_eq!(vector["signature"], b64(&detached.signature), "{name}");
        let status = detached.signer_status.map(|(body, _)| b64(&body));
        assert_eq!(vector["status"], json!(status), "{name}");
    }
}
