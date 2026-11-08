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

//! `spec/pki-path/testdata/ocsp.json`: what this crate makes of OCSP responses, the corpus `go/tipki` is
//! held to. Every response fixture against the certificates it may be about, at several times, online
//! and stapled, with and without a store, and copies of a good response with a byte flipped, which is
//! where two parsers part. Set `TI_PKI_BLESS=1` to write it again after a deliberate change to a rule.
#![cfg(all(
    feature = "brainpool",
    feature = "rsa",
    feature = "dangerous-nonprod",
    feature = "test-util"
))]

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};
use ti_pki::Certificate;
use ti_pki::ocsp::{ResponseCheck, request, verify_response};
use ti_pki::revocation::ResponderAuthorization;
use ti_pki::tsl::Intermediate;
use ti_pki::{Timestamp, TrustStore, algorithms};

/// `TestPki::NOW`, when the fixtures were produced.
const NOW: u64 = 1_767_225_600;

fn pki() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/pki")
}

fn cert(name: &str) -> Certificate {
    let pem = std::fs::read(pki().join(name)).unwrap();
    ti_pki::parse_pem_certificates(&pem).unwrap().remove(0)
}

/// No store; the TSL's CAs without a listed responder; and the same with three responders
/// listed, under a TSP neither CA is listed under, since a listing binds a responder to no
/// CA (OCSP-001).
fn stores() -> [(&'static str, Option<Arc<TrustStore>>); 3] {
    let unlisted = || {
        let intermediate = |file: &str| Intermediate {
            certificate: cert(file),
            provider: "TSP A".to_owned(),
            revoked_since: None,
        };
        TrustStore::new([cert("rca1.pem"), cert("rca7.pem")]).with_intermediates(vec![
            intermediate("sub-ca-hba.pem"),
            intermediate("sub-ca-komp.pem"),
        ])
    };
    let listed = unlisted().with_listed_responders_for_tests(
        LISTED
            .iter()
            .map(|file| (cert(file), "TSP B".to_owned()))
            .collect(),
    );
    [
        ("none", None),
        ("unlisted", Some(Arc::new(unlisted()))),
        ("listed", Some(Arc::new(listed))),
    ]
}

/// The responders the `listed` store lists: one another CA certified, one without
/// id-kp-OCSPSigning, one expired.
const LISTED: [&str; 3] = [
    "ocsp-signer-komp.pem",
    "ocsp-signer-no-eku.pem",
    "ocsp-signer-expired.pem",
];

/// The outcome in words both sides can state: the code, or the verdict with what it rests on.
fn outcome(
    der: &[u8],
    cert: &Certificate,
    issuer: &Certificate,
    check: &ResponseCheck<'_>,
) -> Value {
    match verify_response(der, cert, issuer, check) {
        Err(e) => json!({ "error": e.code.to_string(), "subject": e.subject }),
        Ok(r) => json!({
            "status": r.status.as_str(),
            "reason": r.reason,
            "responder": r.responder_name,
            "embedded": r.responder.is_some(),
            "authorization": r.authorization.as_ref().map(|a| match a {
                ResponderAuthorization::Issuer => "issuer".to_owned(),
                ResponderAuthorization::Delegate => "delegate".to_owned(),
                ResponderAuthorization::TslListed { tsp } => format!("tsl_listed|{tsp}"),
                _ => "other".to_owned(),
            }),
            "produced_at": r.produced_at.map(|t| t.0),
            "this_update": r.this_update.map(|t| t.0),
            "next_update": r.next_update.map(|t| t.0),
            "revoked_at": r.revoked_at.map(|t| t.0),
        }),
    }
}

fn check_at(now: u64, stapled: bool, store: Option<&TrustStore>) -> ResponseCheck<'_> {
    let base = if stapled {
        ResponseCheck::stapled(Timestamp(now), algorithms::DEFAULT)
    } else {
        ResponseCheck::new(Timestamp(now), algorithms::DEFAULT)
    };
    ResponseCheck { store, ..base }
}

fn matrix() -> Vec<Value> {
    let responses = [
        "egk-no-cert-hash",
        "expired-responder",
        "foreign-responder",
        "good",
        "issuer-signed",
        "no-cert-hash",
        "no-eku",
        "revoked",
        "unknown-no-cert-hash",
        "unknown",
        "wrong-cert-hash",
    ];
    let pairs = [
        ("ee-arzt.pem", "sub-ca-hba.pem"),
        ("ee-revoked.pem", "sub-ca-hba.pem"),
        ("sub-ca-hba.pem", "rca1.pem"),
        ("types/type-ch-aut.pem", "sub-ca-komp.pem"),
    ];
    let offsets: [i64; 8] = [0, 37, 38, -37, -38, 3600, 90_000, -90_000];
    let stores = stores();
    let mut cases = Vec::new();
    for response in responses {
        let der = std::fs::read(pki().join(format!("ocsp/{response}.der"))).unwrap();
        for (leaf, issuer) in pairs {
            let (leaf_cert, issuer_cert) = (cert(leaf), cert(issuer));
            for offset in offsets {
                let now = NOW.checked_add_signed(offset).unwrap();
                for stapled in [false, true] {
                    for (store_name, store) in &stores {
                        let check = check_at(now, stapled, store.as_deref());
                        cases.push(json!({
                            "response": response, "cert": leaf, "issuer": issuer, "now": now,
                            "stapled": stapled, "store": store_name,
                            "outcome": outcome(&der, &leaf_cert, &issuer_cert, &check),
                        }));
                    }
                }
            }
        }
    }
    cases
}

/// Every byte of a good response flipped, one at a time: same verdict or same refusal on both sides.
fn mutated() -> Vec<Value> {
    let der = std::fs::read(pki().join("ocsp/good.der")).unwrap();
    let (leaf, issuer) = (cert("ee-arzt.pem"), cert("sub-ca-hba.pem"));
    let check = check_at(NOW, false, None);
    (0..der.len())
        .map(|i| {
            let mut copy = der.clone();
            copy[i] ^= 0x01;
            json!({ "byte": i, "outcome": outcome(&copy, &leaf, &issuer, &check) })
        })
        .collect()
}

fn requests() -> Vec<Value> {
    [
        ("ee-arzt.pem", "sub-ca-hba.pem"),
        ("sub-ca-hba.pem", "rca1.pem"),
        ("types/type-hci-aut.pem", "sub-ca-komp.pem"),
    ]
    .iter()
    .map(|(leaf, issuer)| {
        let bytes = request(&cert(leaf), &cert(issuer));
        let hex = bytes.iter().fold(String::new(), |mut out, b| {
            let _ = write!(out, "{b:02x}");
            out
        });
        json!({ "cert": leaf, "issuer": issuer, "request": hex })
    })
    .collect()
}

/// What gematik's responders really sent, at the time they sent it.
fn real() -> Vec<Value> {
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let file_cert = |name: &str| {
        let pem = std::fs::read(fixtures.join(name)).unwrap();
        ti_pki::parse_pem_certificates(&pem).unwrap().remove(0)
    };
    let responses = [
        (
            "ocsp-smcb-ca51-test-only.der",
            "smcb-ee-test-only.pem",
            "smcb-ca51-test-only.pem",
        ),
        (
            "ocsp-smcb-ca51-test-only-sha1.der",
            "smcb-ee-test-only.pem",
            "smcb-ca51-test-only.pem",
        ),
    ];
    let mut cases = Vec::new();
    for (response, leaf, issuer) in responses {
        let der = std::fs::read(fixtures.join(response)).unwrap();
        let (leaf_cert, issuer_cert) = (file_cert(leaf), file_cert(issuer));
        let produced = verify_response(
            &der,
            &leaf_cert,
            &issuer_cert,
            &ResponseCheck {
                max_response_age: Duration::from_secs(u64::from(u32::MAX) * 4),
                ..check_at(NOW, false, None)
            },
        );
        let now = match &produced {
            Ok(r) => r.produced_at.map_or(NOW, |t| t.0),
            Err(_) => NOW,
        };
        let check = check_at(now, false, None);
        cases.push(json!({
            "response": response, "cert": leaf, "issuer": issuer, "now": now,
            "outcome": outcome(&der, &leaf_cert, &issuer_cert, &check),
        }));
    }
    cases
}

/// OCSP-002: bytes no signature covers are still read strictly: the tag of the signature's
/// AlgorithmIdentifier, and the unused bits of the response's and the embedded certificate's signature.
#[test]
fn ocsp_002_what_no_signature_covers_is_read_strictly() {
    let der = std::fs::read(pki().join("ocsp/good.der")).unwrap();
    let (leaf, issuer) = (cert("ee-arzt.pem"), cert("sub-ca-hba.pem"));
    let check = check_at(NOW, false, None);
    for (byte, code) in [
        (311, "ocsp_unavailable"),
        (325, "ocsp_unavailable"),
        (782, "ocsp_responder_untrusted"),
    ] {
        let mut copy = der.clone();
        copy[byte] ^= 0x01;
        let outcome = outcome(&copy, &leaf, &issuer, &check);
        assert_eq!(outcome["error"], code, "byte {byte}: {outcome}");
    }
}

/// PATH-007: a compressed point is refused when the certificate is read, whatever it is for.
#[test]
fn path_007_a_compressed_key_does_not_parse() {
    let pem = std::fs::read(pki().join("tsl-signer/signer-compressed-key.pem")).unwrap();
    assert!(ti_pki::parse_pem_certificates(&pem).is_err());
}

/// OCSP-001, OCSP-002 and OCSP-003: the corpus is what this crate says, a responder the TSL
/// lists included.
#[test]
fn ocsp_001_the_corpus_is_what_ti_pki_says() {
    let matrix = matrix();
    let at_now = |response: &str, store: &str| {
        matrix
            .iter()
            .find(|c| {
                c["response"] == response
                    && c["cert"] == "ee-arzt.pem"
                    && c["now"] == NOW
                    && c["stapled"] == false
                    && c["store"] == store
            })
            .unwrap()["outcome"]
            .clone()
    };
    // Another CA's responder: authorized by its listing alone, untrusted without it.
    assert_eq!(
        at_now("foreign-responder", "listed")["authorization"],
        "tsl_listed|TSP B"
    );
    assert_eq!(
        at_now("foreign-responder", "unlisted")["error"],
        "ocsp_responder_untrusted"
    );
    // The CA's own delegate needs no listing.
    assert_eq!(at_now("good", "unlisted")["authorization"], "delegate");
    // A listing waives neither validity nor id-kp-OCSPSigning.
    for response in ["expired-responder", "no-eku"] {
        assert_eq!(
            at_now(response, "listed")["error"],
            "ocsp_responder_untrusted",
            "{response}"
        );
    }
    let corpus =
        json!({ "matrix": matrix, "mutated": mutated(), "requests": requests(), "real": real() });
    let written = serde_json::to_string(&corpus).unwrap() + "\n";
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../spec/pki-path/testdata/ocsp.json");
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
