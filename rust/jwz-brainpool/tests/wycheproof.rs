//! Wycheproof brainpoolP256r1 vectors (`tests/data/wycheproof`, see its PROVENANCE.md):
//! ECDSA through JWK parsing and both key types, ECDH through `Bp256`.
//!
//! `valid` must pass and `invalid` must fail; `acceptable` may go either way.

use std::sync::Arc;

use jwz::crypto::Ecdh;
use jwz::crypto::rustcrypto::RustCrypto;
use jwz::jwk::{EcKey, Jwk, KeyMaterial};
use jwz::keys::{Signature, SoftwareKey, Verifier};
use jwz_brainpool::{BP256R1, Bp256, BrainpoolEs256Key};
use serde_json::Value;

fn load(name: &str) -> Value {
    let path = format!(
        "{}/tests/data/wycheproof/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap()
}

fn hex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd hex {s}");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn s<'a>(v: &'a Value, key: &str) -> &'a str {
    v[key].as_str().unwrap_or_else(|| panic!("{key} missing"))
}

fn run(file: &str, mut case: impl FnMut(&Value, &Value) -> Option<bool>) -> usize {
    let data = load(file);
    let mut checked = 0;
    for group in data["testGroups"].as_array().unwrap() {
        for test in group["tests"].as_array().unwrap() {
            let Some(passed) = case(group, test) else {
                continue;
            };
            match s(test, "result") {
                "valid" => assert!(
                    passed,
                    "{file} tcId {} should pass: {}",
                    test["tcId"], test["comment"]
                ),
                "invalid" => assert!(
                    !passed,
                    "{file} tcId {} should fail: {}",
                    test["tcId"], test["comment"]
                ),
                _ => {}
            }
            checked += 1;
        }
    }
    checked
}

/// The group's key as a `BP-256` JWK, from its uncompressed point.
fn group_jwk(group: &Value) -> Jwk {
    let point = hex(s(&group["publicKey"], "uncompressed"));
    assert_eq!((point.len(), point[0]), (65, 4));
    Jwk::new(KeyMaterial::Ec(EcKey::from_point("BP-256", &point)))
}

#[test]
fn wycheproof_ecdsa_bp256r1_sha256_p1363_as_bp256r1_and_as_es256() {
    let registry = jwz_brainpool::registry();
    let backend = Arc::new(jwz_brainpool::backend(RustCrypto::new()));
    let checked = run(
        "ecdsa_brainpoolP256r1_sha256_p1363_test.json",
        |group, test| {
            let jwk = group_jwk(group);
            let msg = hex(s(test, "msg"));
            let sig = Signature::from(hex(s(test, "sig")));
            let bp256r1 = SoftwareKey::from_jwk(&jwk, BP256R1, &registry, Arc::clone(&backend))
                .map(|key| key.verify(&msg, &sig).is_ok());
            let es256 = BrainpoolEs256Key::from_jwk(&jwk).map(|key| key.verify(&msg, &sig).is_ok());
            // Both keys run the same primitive: they must agree on every vector.
            assert_eq!(
                bp256r1.unwrap_or(false),
                es256.unwrap_or(false),
                "tcId {}",
                test["tcId"]
            );
            Some(bp256r1.unwrap_or(false))
        },
    );
    assert!(checked > 200, "{checked}");
}

/// SubjectPublicKeyInfo of an uncompressed brainpoolP256r1 point, up to the point.
const SPKI_PREFIX: &str = "305a301406072a8648ce3d020106092b2403030208010107034200";

#[test]
fn wycheproof_ecdh_bp256() {
    let checked = run("ecdh_brainpoolP256r1_test.json", |_, test| {
        let public = s(test, "public");
        let point = hex(public.strip_prefix(SPKI_PREFIX)?);
        if point.len() != 65 {
            return None;
        }
        let raw = hex(s(test, "private"));
        let trimmed: Vec<u8> = raw.iter().copied().skip_while(|b| *b == 0).collect();
        if trimmed.len() > 32 {
            return None;
        }
        let mut secret = vec![0u8; 32 - trimmed.len()];
        secret.extend_from_slice(&trimmed);
        match Bp256.agree(&secret, &point) {
            Ok(shared) => Some(*shared == hex(s(test, "shared"))),
            Err(_) => Some(false),
        }
    });
    assert!(checked > 100, "{checked}");
}
