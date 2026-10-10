//! Wycheproof vectors (`tests/data/wycheproof`, see its PROVENANCE.md) through jwz's
//! crypto backend and, where the vectors carry JWKs, through JWK parsing and
//! `SoftwareKey`: P-256 ECDSA, Ed25519, P-256 ECDH, AES-GCM and AES Key Wrap.
//!
//! `valid` must pass and `invalid` must fail; `acceptable` may go either way.
#![cfg(feature = "crypto-rustcrypto")]

use std::sync::Arc;

use jwz::crypto::Backend;
use jwz::crypto::rustcrypto::RustCrypto;
use jwz::jwa::{ContentEncryptionAlgorithm, Curve, Registry, SignatureAlgorithm};
use jwz::jwk::Jwk;
use jwz::keys::{Signature, SoftwareKey, Verifier};
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

/// Runs every test of every group, checking `outcome` against `result`.
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

#[test]
fn wycheproof_ecdsa_p256_sha256_p1363_through_jwk_and_software_key() {
    let registry = Registry::standard();
    let backend = Arc::new(RustCrypto::new());
    let checked = run("ecdsa_secp256r1_sha256_p1363_test.json", |group, test| {
        let jwk = ecdsa_jwk(group);
        let key = SoftwareKey::from_jwk(
            &jwk,
            SignatureAlgorithm::ES256,
            &registry,
            Arc::clone(&backend),
        );
        let Ok(key) = key else {
            return Some(false);
        };
        let sig = Signature::from(hex(s(test, "sig")));
        Some(key.verify(&hex(s(test, "msg")), &sig).is_ok())
    });
    assert!(checked > 200, "{checked}");
}

/// The group's JWK, or one built from its uncompressed point where the vectors give
/// only the point (the groups testing edge-case public keys).
fn ecdsa_jwk(group: &Value) -> Jwk {
    if group["publicKeyJwk"].is_object() {
        return Jwk::parse(&group["publicKeyJwk"].to_string()).unwrap();
    }
    let point = hex(s(&group["publicKey"], "uncompressed"));
    assert_eq!((point.len(), point[0]), (65, 4));
    Jwk::new(jwz::jwk::KeyMaterial::Ec(jwz::jwk::EcKey {
        crv: "P-256".into(),
        x: point[1..33].to_vec(),
        y: point[33..].to_vec(),
        d: None,
    }))
}

#[test]
fn wycheproof_ed25519_through_jwk_and_software_key() {
    let registry = Registry::standard();
    let backend = Arc::new(RustCrypto::new());
    let checked = run("ed25519_test.json", |group, test| {
        let jwk = Jwk::parse(&group["publicKeyJwk"].to_string()).unwrap();
        let Ok(key) = SoftwareKey::from_jwk(
            &jwk,
            SignatureAlgorithm::EDDSA,
            &registry,
            Arc::clone(&backend),
        ) else {
            return Some(false);
        };
        let sig = Signature::from(hex(s(test, "sig")));
        Some(key.verify(&hex(s(test, "msg")), &sig).is_ok())
    });
    assert!(checked > 100, "{checked}");
}

#[test]
fn wycheproof_ecdh_p256_ecpoint() {
    let backend = RustCrypto::new();
    let ecdh = backend.ecdh(Curve::P256).unwrap();
    let checked = run("ecdh_secp256r1_ecpoint_test.json", |_, test| {
        // The private key is a DER integer: strip a sign byte, left-pad to 32 bytes.
        let raw = hex(s(test, "private"));
        let trimmed: Vec<u8> = raw.iter().copied().skip_while(|b| *b == 0).collect();
        if trimmed.len() > 32 {
            return None;
        }
        let mut secret = vec![0u8; 32 - trimmed.len()];
        secret.extend_from_slice(&trimmed);
        match ecdh.agree(&secret, &hex(s(test, "public"))) {
            Ok(shared) => Some(*shared == hex(s(test, "shared"))),
            Err(_) => Some(false),
        }
    });
    assert!(checked > 300, "{checked}");
}

#[test]
fn wycheproof_aes_gcm_with_jose_parameters() {
    let backend = RustCrypto::new();
    let checked = run("aes_gcm_test.json", |group, test| {
        // RFC 7518 §5.3: JOSE uses a 96-bit IV and a 128-bit tag only.
        if group["ivSize"] != 96 || group["tagSize"] != 128 {
            return None;
        }
        let enc = match group["keySize"].as_u64() {
            Some(128) => ContentEncryptionAlgorithm::A128GCM,
            Some(192) => ContentEncryptionAlgorithm::A192GCM,
            Some(256) => ContentEncryptionAlgorithm::A256GCM,
            _ => return None,
        };
        let aead = backend.aead(enc).unwrap();
        let (key, iv, associated) = (hex(s(test, "key")), hex(s(test, "iv")), hex(s(test, "aad")));
        let (msg, ct, tag) = (hex(s(test, "msg")), hex(s(test, "ct")), hex(s(test, "tag")));
        let opened = aead.open(&key, &iv, &associated, &ct, &tag);
        let passed = opened.is_ok_and(|plain| plain.as_slice() == msg.as_slice());
        if passed {
            // A vector that opens must also be what sealing produces.
            let sealed = aead.seal(&key, &iv, &associated, &msg).unwrap();
            assert_eq!(
                (sealed.ciphertext, sealed.tag),
                (ct, tag),
                "tcId {}",
                test["tcId"]
            );
        }
        Some(passed)
    });
    assert!(checked > 100, "{checked}");
}

#[test]
fn wycheproof_aes_key_wrap() {
    let backend = RustCrypto::new();
    let checked = run("aes_wrap_test.json", |group, test| {
        let kek_len = usize::try_from(group["keySize"].as_u64()? / 8).ok()?;
        let wrap = backend.key_wrap(kek_len)?;
        let (kek, msg, ct) = (hex(s(test, "key")), hex(s(test, "msg")), hex(s(test, "ct")));
        let passed = wrap
            .unwrap(&kek, &ct)
            .is_ok_and(|plain| plain.as_slice() == msg.as_slice());
        if passed {
            assert_eq!(wrap.wrap(&kek, &msg).unwrap(), ct, "tcId {}", test["tcId"]);
        }
        Some(passed)
    });
    assert!(checked > 100, "{checked}");
}
