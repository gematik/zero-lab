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

//! `spec/pki-validation/testdata`: the cases of the `ti` profile, each judged as the manifest
//! expects, with the TSL's CAs standing in for a verified list and the case's OCSP answers
//! played back as the responder's. The `web` cases are `ti-tls`'s.
#![cfg(all(feature = "load", feature = "test-util"))]

use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;

use futures_lite::future::block_on;
use serde_json::Value;
use ti_pki::load::{MockTransport, TransportError, TransportErrorKind};
use ti_pki::ocsp::OcspChecker;
use ti_pki::tls::ServerCheck;
use ti_pki::tsl::Intermediate;
use ti_pki::{Certificate, CertificateType, Timestamp, TrustConfig, TrustStore};

/// 2026-01-01T00:00:00Z, the `at` of every case.
const AT: Timestamp = Timestamp(1_767_225_600);

fn testdata() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../spec/pki-validation/testdata")
}

fn bytes(name: &str) -> Vec<u8> {
    std::fs::read(testdata().join(name)).unwrap_or_else(|e| panic!("{name}: {e}"))
}

fn cert(name: &str) -> Certificate {
    ti_pki::parse_pem_certificates(&bytes(name))
        .unwrap()
        .remove(0)
}

fn check(trust: &Value) -> ServerCheck {
    let roots: Vec<Certificate> = trust["roots"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| cert(r.as_str().unwrap()))
        .collect();
    let config = TrustConfig::for_lab_ca(roots[0].der());
    let Some(cas) = trust["tsl_cas"].as_array() else {
        return ServerCheck::new(config, None);
    };
    let mut intermediates = Vec::new();
    let mut types = Vec::new();
    for ca in cas {
        let certificate = cert(ca["cert"].as_str().unwrap());
        let oids = ca["types"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| {
                CertificateType::from_str(t.as_str().unwrap())
                    .unwrap()
                    .oid()
            })
            .collect();
        types.push((certificate.clone(), oids));
        intermediates.push(Intermediate {
            certificate,
            provider: "TEST-ONLY".into(),
            revoked_since: None,
        });
    }
    let store = TrustStore::new(roots)
        .with_intermediates(intermediates)
        .with_tsl_ca_types_for_tests(types);
    ServerCheck::new(config, Some(Arc::new(store)))
}

/// TLSV-020, TLSV-021, TLSV-022, TLSV-023, TLSV-024, TLSV-030, TLSV-031, TLSV-032 and
/// TLSV-033: every `ti` case of the corpus ends in the code and warnings it expects; a
/// responder answers only when a case gives it an answer.
#[test]
fn tlsv_030_the_ti_cases_are_judged_as_the_corpus_says() {
    let manifest: Value = serde_json::from_slice(&bytes("manifest.json")).unwrap();
    let mut judged = 0;
    for case in manifest["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let trust = &manifest["trust"][case["trust"].as_str().unwrap()];
        if trust["profile"] != "ti" {
            continue;
        }
        assert_eq!(case["at"], "2026-01-01T00:00:00Z", "{name}");
        let chain: Vec<Certificate> = case["chain"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| cert(c.as_str().unwrap()))
            .collect();
        let stapled = case["stapled_ocsp"].as_str().map(bytes);
        let answer = match case["responder_ocsp"].as_str() {
            Some(file) => Ok(bytes(file)),
            None => Err(TransportError {
                kind: TransportErrorKind::Network,
                message: "no responder".into(),
                retryable: true,
            }),
        };
        let check = check(trust);
        let responder = OcspChecker::new(
            &TrustConfig::for_lab_ca(chain[0].der()),
            MockTransport::posting([answer]),
            || AT,
        );
        let verdict = block_on(check.verify(
            &chain,
            case["host"].as_str().unwrap(),
            stapled.as_deref(),
            AT,
            &responder,
        ));
        assert_eq!(
            verdict.code.as_str(),
            case["expect"].as_str().unwrap(),
            "{name}: {}",
            verdict.detail
        );
        let warnings: Vec<&str> = case["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .map(|w| w.as_str().unwrap())
            .collect();
        assert_eq!(verdict.warnings, warnings, "{name}");
        judged += 1;
    }
    assert!(judged >= 20, "only {judged} ti cases");
}
