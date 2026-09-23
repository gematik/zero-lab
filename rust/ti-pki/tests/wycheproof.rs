//! Wycheproof ECDSA verification vectors against the algorithm set.
//!
//! Vectors from <https://github.com/C2SP/wycheproof> (Apache-2.0), `testvectors_v1/`,
//! commit 3fa63dd0344abb611f1fb1d77e119938603ea230. `acceptable` cases (legacy encodings a
//! verifier may take or refuse) are not asserted.

use rustls_pki_types::SignatureVerificationAlgorithm;
use serde_json::Value;

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn run(file: &str, alg: &dyn SignatureVerificationAlgorithm) {
    let path = format!("{}/tests/wycheproof/{file}", env!("CARGO_MANIFEST_DIR"));
    let vectors: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let mut checked = 0;
    for group in vectors["testGroups"].as_array().unwrap() {
        // ECDSA groups carry the SEC1 point, RSA groups the PKCS#1 key: each is the
        // raw subjectPublicKey the trait receives.
        let key = group["publicKey"]["uncompressed"]
            .as_str()
            .or_else(|| group["publicKeyAsn"].as_str())
            .map(hex)
            .unwrap();
        for test in group["tests"].as_array().unwrap() {
            let msg = hex(test["msg"].as_str().unwrap());
            let sig = hex(test["sig"].as_str().unwrap());
            let verified = alg.verify_signature(&key, &msg, &sig).is_ok();
            match test["result"].as_str().unwrap() {
                "valid" => assert!(verified, "{file} tcId {} must verify", test["tcId"]),
                "invalid" => assert!(!verified, "{file} tcId {} must fail", test["tcId"]),
                _ => continue,
            }
            checked += 1;
        }
    }
    assert!(checked > 50, "{file}: only {checked} vectors checked");
}

#[test]
fn p256_sha256() {
    run(
        "ecdsa_secp256r1_sha256_test.json",
        ti_pki::algorithms::ECDSA_P256_SHA256,
    );
}

#[test]
fn p384_sha384() {
    run(
        "ecdsa_secp384r1_sha384_test.json",
        ti_pki::algorithms::ECDSA_P384_SHA384,
    );
}

#[cfg(feature = "brainpool")]
#[test]
fn brainpool_p256r1_sha256() {
    run(
        "ecdsa_brainpoolP256r1_sha256_test.json",
        ti_pki::algorithms::brainpool::ECDSA_BP256R1_SHA256,
    );
}

#[cfg(feature = "brainpool")]
#[test]
fn brainpool_p384r1_sha384() {
    run(
        "ecdsa_brainpoolP384r1_sha384_test.json",
        ti_pki::algorithms::brainpool::ECDSA_BP384R1_SHA384,
    );
}

#[cfg(feature = "rsa")]
#[test]
fn rsa_pkcs1_sha256() {
    run(
        "rsa_signature_2048_sha256_test.json",
        ti_pki::algorithms::rsa::RSA_PKCS1_SHA256,
    );
}

#[cfg(feature = "rsa")]
#[test]
fn rsa_pkcs1_sha384() {
    run(
        "rsa_signature_3072_sha384_test.json",
        ti_pki::algorithms::rsa::RSA_PKCS1_SHA384,
    );
}

#[cfg(feature = "rsa")]
#[test]
fn rsa_pkcs1_sha512() {
    run(
        "rsa_signature_4096_sha512_test.json",
        ti_pki::algorithms::rsa::RSA_PKCS1_SHA512,
    );
}

#[cfg(feature = "rsa")]
#[test]
fn rsa_pss_sha256() {
    run(
        "rsa_pss_2048_sha256_mgf1_32_test.json",
        ti_pki::algorithms::rsa::RSA_PSS_SHA256,
    );
}

#[cfg(feature = "rsa")]
#[test]
fn rsa_pss_sha384() {
    run(
        "rsa_pss_2048_sha384_mgf1_48_test.json",
        ti_pki::algorithms::rsa::RSA_PSS_SHA384,
    );
}

#[cfg(feature = "rsa")]
#[test]
fn rsa_pss_sha512() {
    run(
        "rsa_pss_4096_sha512_mgf1_64_test.json",
        ti_pki::algorithms::rsa::RSA_PSS_SHA512,
    );
}
