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

//! `spec/pki-validation/testdata`: the cases of the `web` profile, each judged as the manifest
//! expects, with the case's root standing in for the system store and its OCSP answer and CRL
//! as the network. The `ti` cases are ti-pki's.

use std::path::{Path, PathBuf};

use futures_lite::future::block_on;
use rustls_pki_types::CertificateDer;
use serde_json::Value;
use ti_pki::Timestamp;
use ti_tls::{Fetch, WebCheck};

/// 2026-01-01T00:00:00Z, the `at` of every case.
const AT: Timestamp = Timestamp(1_767_225_600);

fn testdata() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../spec/pki-validation/testdata")
}

fn bytes(name: &str) -> Vec<u8> {
    std::fs::read(testdata().join(name)).unwrap_or_else(|e| panic!("{name}: {e}"))
}

fn der(name: &str) -> CertificateDer<'static> {
    CertificateDer::from(
        ti_pki::parse_pem_certificates(&bytes(name))
            .unwrap()
            .remove(0)
            .der()
            .to_vec(),
    )
}

/// The network of one case: the responder and the CRL host answer with its files.
struct Network {
    ocsp: Option<Vec<u8>>,
    crl: Option<Vec<u8>>,
}

impl Fetch for Network {
    async fn ocsp(&self, _: &str, _: &[u8]) -> Option<Vec<u8>> {
        self.ocsp.clone()
    }

    async fn crl(&self, _: &str) -> Option<Vec<u8>> {
        self.crl.clone()
    }
}

/// TLSV-020, TLSV-021, TLSV-022, TLSV-023, TLSV-024, TLSV-040, TLSV-041, TLSV-042, TLSV-043,
/// TLSV-044 and TLSV-045: every `web` case of the corpus ends in the code it expects.
#[test]
fn tlsv_040_the_web_cases_are_judged_as_the_corpus_says() {
    let manifest: Value = serde_json::from_slice(&bytes("manifest.json")).unwrap();
    let mut judged = 0;
    for case in manifest["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let trust = &manifest["trust"][case["trust"].as_str().unwrap()];
        if trust["profile"] != "web" {
            continue;
        }
        assert_eq!(case["at"], "2026-01-01T00:00:00Z", "{name}");
        let check = WebCheck::new(
            trust["roots"]
                .as_array()
                .unwrap()
                .iter()
                .map(|r| der(r.as_str().unwrap())),
        );
        let chain: Vec<CertificateDer<'static>> = case["chain"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| der(c.as_str().unwrap()))
            .collect();
        let network = Network {
            ocsp: case["responder_ocsp"].as_str().map(bytes),
            crl: case["crl"].as_str().map(bytes),
        };
        let stapled = case["stapled_ocsp"].as_str().map(bytes);
        let verdict = block_on(check.verify(
            &chain,
            case["host"].as_str().unwrap(),
            stapled.as_deref(),
            AT,
            &network,
        ));
        assert_eq!(
            verdict.code.as_str(),
            case["expect"].as_str().unwrap(),
            "{name}: {}",
            verdict.detail
        );
        assert!(case["warnings"].as_array().unwrap().is_empty(), "{name}");
        judged += 1;
    }
    assert!(judged >= 20, "only {judged} web cases");
}
