//! JWE against RFC 7520 §5.6 and §5.8-5.12, ECDH-ES against RFC 7518 Appendix C, round
//! trips for every implemented `alg` × `enc`, the structural and key negatives, the JSON
//! serializations with several recipients, async key agreement and a curve added through
//! the `Extended` backend.
#![cfg(all(feature = "crypto-rustcrypto", feature = "jwe"))]

use std::sync::Arc;

use jwz::ErrorCode;
use jwz::crypto::rustcrypto::RustCrypto;
use jwz::crypto::{Backend, CryptoError, Ecdh, Extended, KeyPair, Rng};
use jwz::header::HeaderParams;
use jwz::jwa::{
    ContentEncryptionAlgorithm as Enc, Curve, CurveEntry, KeyEncryptionAlgorithm as Alg, KeyType,
    Registry, Support,
};
use jwz::jwe::json::Recipient;
use jwz::jwe::{self, DecryptionKey, EncryptionKey, Jwe};
use jwz::jwk::Jwk;
use jwz::keys::{SoftwareAgreementKey, SymmetricKey};
use jwz::profile::{Policy, Profile};
use serde_json::{Value, json};

fn backend() -> Arc<RustCrypto> {
    Arc::new(RustCrypto::new())
}

fn interop() -> Policy {
    Profile::rfc7518_interop(&Registry::standard()).policy
}

fn code<T>(r: Result<T, jwz::Error>) -> Result<T, ErrorCode> {
    r.map_err(|e| e.code())
}

fn b64(bytes: &[u8]) -> String {
    jwz::b64::encode(bytes)
}

/// RFC 7520 Figure 72.
const PLAINTEXT: &str = "You can trust us to stick with you through thick and \
thin\u{2013}to the bitter end. And you can trust us to keep any secret of yours\u{2013}\
closer than you keep it yourself. But you cannot trust us to let you face trouble \
alone, and go off without a word. We are your friends, Frodo.";

/// RFC 7520 Figure 151 (§5.8) and Figure 130 (§5.6).
const A128KW_KEY: &str = r#"{"kty":"oct","kid":"81b20965-8332-43d9-a468-82160ad91ac8",
  "use":"enc","alg":"A128KW","k":"GZy6sIZ6wl9NJOKB-jnmVQ"}"#;
const DIR_KEY: &str = r#"{"kty":"oct","kid":"77c7e2b8-6e13-45cf-8672-617b5b45243a",
  "use":"enc","alg":"A128GCM","k":"XctOhJAkA-pD9Lh7ZgW_2A"}"#;

fn symmetric(jwk: &str) -> SymmetricKey {
    SymmetricKey::from_jwk(&Jwk::parse(jwk).unwrap(), &Registry::standard()).unwrap()
}

fn rfc7520(name: &str) -> String {
    let all: serde_json::Map<String, Value> =
        serde_json::from_str(include_str!("data/rfc7520/jwe.json")).unwrap();
    all[name].as_str().unwrap().to_string()
}

fn decrypt_compact(token: &str, key: DecryptionKey<'_>) -> Result<Vec<u8>, ErrorCode> {
    let registry = Registry::standard();
    let jwe = code(Jwe::parse(token, &interop(), &registry))?;
    code(jwe.decrypt(key, backend().as_ref())).map(|d| d.plaintext().to_vec())
}

fn decrypt_json(text: &str, key: DecryptionKey<'_>) -> Result<Vec<u8>, ErrorCode> {
    let registry = Registry::standard();
    let mut all = code(jwe::json::parse(text, &interop(), &registry))?;
    assert_eq!(all.len(), 1);
    code(all.remove(0).decrypt(key, backend().as_ref())).map(|d| d.plaintext().to_vec())
}

#[test]
fn rfc_7520_5_6_dir_a128gcm() {
    let key = symmetric(DIR_KEY);
    let key = DecryptionKey::Symmetric(&key);
    for (name, plaintext) in [
        (
            "5.6 JWE Compact Serialization",
            decrypt_compact(&rfc7520("5.6 JWE Compact Serialization"), key),
        ),
        (
            "5.6 General JWE JSON Serialization",
            decrypt_json(&rfc7520("5.6 General JWE JSON Serialization"), key),
        ),
    ] {
        assert_eq!(plaintext.unwrap(), PLAINTEXT.as_bytes(), "{name}");
    }
}

#[test]
fn rfc_7520_5_8_a128kw_a128gcm() {
    let key = symmetric(A128KW_KEY);
    let key = DecryptionKey::Symmetric(&key);
    let compact = rfc7520("5.8 JWE Compact Serialization");
    let jwe = Jwe::parse(&compact, &interop(), &Registry::standard()).unwrap();
    assert_eq!(jwe.algorithm(), Alg::A128KW);
    assert_eq!(jwe.content_encryption(), Enc::A128GCM);
    assert_eq!(
        jwe.header().kid(),
        Some("81b20965-8332-43d9-a468-82160ad91ac8")
    );
    assert_eq!(
        decrypt_compact(&compact, key).unwrap(),
        PLAINTEXT.as_bytes()
    );
    for name in [
        "5.8 General JWE JSON Serialization",
        "5.8 Flattened JWE JSON Serialization",
        // §5.10: aad authenticated with the protected header.
        "5.10 General JWE JSON Serialization",
        "5.10 Flattened JWE JSON Serialization",
        // §5.11: alg and kid in the shared unprotected header.
        "5.11 General JWE JSON Serialization",
        "5.11 Flattened JWE JSON Serialization",
    ] {
        assert_eq!(
            decrypt_json(&rfc7520(name), key).unwrap(),
            PLAINTEXT.as_bytes(),
            "{name}"
        );
    }
}

#[test]
fn rfc_7520_5_9_zip_and_5_12_unprotected_enc_are_refused() {
    let key = symmetric(A128KW_KEY);
    let key = DecryptionKey::Symmetric(&key);
    assert_eq!(
        decrypt_compact(&rfc7520("5.9 JWE Compact Serialization"), key),
        Err(ErrorCode::PolicyViolation)
    );
    assert_eq!(
        decrypt_json(&rfc7520("5.9 Flattened JWE JSON Serialization"), key),
        Err(ErrorCode::PolicyViolation)
    );
    for name in [
        "5.12 General JWE JSON Serialization",
        "5.12 Flattened JWE JSON Serialization",
    ] {
        assert_eq!(
            decrypt_json(&rfc7520(name), key),
            Err(ErrorCode::Malformed),
            "{name}"
        );
    }
}

#[test]
fn rfc_7520_5_10_aad_is_authenticated() {
    let key = symmetric(A128KW_KEY);
    let mut object: Value =
        serde_json::from_str(&rfc7520("5.10 Flattened JWE JSON Serialization")).unwrap();
    object["aad"] = Value::String(b64(b"[\"vcard\",[]]"));
    assert_eq!(
        decrypt_json(&object.to_string(), DecryptionKey::Symmetric(&key)),
        Err(ErrorCode::VerificationFailed)
    );
}

/// RFC 7518 Appendix C, Alice's ephemeral key and Bob's static key.
const BOB: &str = r#"{"kty":"EC","crv":"P-256",
  "x":"weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ",
  "y":"e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck",
  "d":"VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw"}"#;

fn appendix_c_header() -> Value {
    json!({
        "alg": "ECDH-ES",
        "enc": "A128GCM",
        "apu": "QWxpY2U",
        "apv": "Qm9i",
        "epk": {
            "kty": "EC",
            "crv": "P-256",
            "x": "gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0",
            "y": "SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps"
        }
    })
}

/// A compact JWE with `header`, sealed under `cek` (or with a dummy ciphertext).
fn handmade(header: &Value, encrypted_key: &[u8], cek: Option<&[u8]>) -> String {
    let protected = b64(header.to_string().as_bytes());
    let iv = [7u8; 12];
    let (ciphertext, tag) = match cek {
        Some(cek) => {
            let backend = backend();
            let aead = backend.aead(Enc::A128GCM).unwrap();
            let sealed = aead
                .seal(cek, &iv, protected.as_bytes(), b"Appendix C")
                .unwrap();
            (sealed.ciphertext, sealed.tag)
        }
        None => (b"ciphertext".to_vec(), vec![0u8; 16]),
    };
    format!(
        "{protected}.{}.{}.{}.{}",
        b64(encrypted_key),
        b64(&iv),
        b64(&ciphertext),
        b64(&tag)
    )
}

fn bob() -> SoftwareAgreementKey<RustCrypto> {
    SoftwareAgreementKey::from_jwk(&Jwk::parse(BOB).unwrap(), &Registry::standard(), backend())
        .unwrap()
}

#[test]
fn rfc_7518_appendix_c_recipient_derives_the_rfc_cek() {
    // The CEK the RFC derives ("VqqN6vgjbSBcIijNcacQGg"): a token sealed under it
    // decrypts with Bob's key only if Z, the KDF and apu/apv handling all match.
    let cek = jwz::b64::decode("VqqN6vgjbSBcIijNcacQGg", "cek").unwrap();
    let token = handmade(&appendix_c_header(), b"", Some(&cek));
    let bob = bob();
    assert_eq!(
        decrypt_compact(&token, DecryptionKey::Agreement(&bob)).unwrap(),
        b"Appendix C"
    );
    // apv is part of the KDF input: the same token claiming another apv does not open.
    let mut other = appendix_c_header();
    other["apv"] = json!("Q2Fyb2w");
    let token = handmade(&other, b"", Some(&cek));
    assert_eq!(
        decrypt_compact(&token, DecryptionKey::Agreement(&bob)),
        Err(ErrorCode::VerificationFailed)
    );
}

#[test]
fn rfc_7518_4_6_1_epk_apu_apv_negatives() {
    let bob = bob();
    let key = DecryptionKey::Agreement(&bob);
    let with = |path: &str, value: Value| {
        let mut header = appendix_c_header();
        if let Some(member) = path.strip_prefix("epk.") {
            header["epk"][member] = value;
        } else if value.is_null() {
            header.as_object_mut().unwrap().remove(path);
        } else {
            header[path] = value;
        }
        handmade(&header, b"", None)
    };
    for (token, expected, what) in [
        (with("epk", Value::Null), ErrorCode::MissingMember, "no epk"),
        (
            with("epk", json!("x")),
            ErrorCode::InvalidMember,
            "epk string",
        ),
        (
            with(
                "epk.d",
                json!("VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw"),
            ),
            ErrorCode::InvalidMember,
            "private epk",
        ),
        (
            with("epk.x", json!("gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5")),
            ErrorCode::KeyLength,
            "short x",
        ),
        (
            with("epk.crv", json!("P-384")),
            ErrorCode::KeyLength,
            "coordinates of another curve",
        ),
        (
            with("epk.crv", json!("brainpoolP256r1")),
            ErrorCode::UnknownCurve,
            "unknown curve",
        ),
        (
            with("epk.kty", json!("OKP")),
            ErrorCode::UnknownCurve,
            "OKP on an EC curve",
        ),
        (
            // Off the curve: x of Alice, y of Bob.
            with(
                "epk.y",
                json!("e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck"),
            ),
            ErrorCode::Crypto(CryptoError::InvalidKey),
            "point not on the curve",
        ),
        (
            with("apu", json!(1)),
            ErrorCode::InvalidMember,
            "apu number",
        ),
        (with("apv", json!("Qm9i=")), ErrorCode::Base64, "apv padded"),
    ] {
        assert_eq!(decrypt_compact(&token, key), Err(expected), "{what}");
    }
}

#[test]
fn rfc_7516_5_2_structure_negatives() {
    let a128kw = symmetric(A128KW_KEY);
    let dir = symmetric(DIR_KEY);
    let header = |alg: &str| json!({"alg": alg, "enc": "A128GCM"});
    let token = rfc7520("5.8 JWE Compact Serialization");
    let parts: Vec<&str> = token.split('.').collect();
    let replaced = |index: usize, value: &str| {
        let mut parts = parts.clone();
        parts[index] = value;
        parts.join(".")
    };
    let key = DecryptionKey::Symmetric(&a128kw);
    for (token, expected, what) in [
        (parts[..4].join("."), ErrorCode::Malformed, "four parts"),
        (format!("{token}."), ErrorCode::Malformed, "six parts"),
        (
            replaced(2, &b64(&[0; 16])),
            ErrorCode::InvalidMember,
            "16-byte iv",
        ),
        (
            replaced(4, &b64(&[0; 12])),
            ErrorCode::InvalidMember,
            "12-byte tag",
        ),
        (
            replaced(1, ""),
            ErrorCode::Malformed,
            "A128KW without encrypted key",
        ),
        (replaced(3, "AA=="), ErrorCode::Base64, "padded ciphertext"),
        (
            replaced(3, "AwliP-KmWgsZ37Bv"),
            ErrorCode::VerificationFailed,
            "other ciphertext",
        ),
        (
            replaced(4, &b64(&[0; 16])),
            ErrorCode::VerificationFailed,
            "other tag",
        ),
        (
            replaced(1, &b64(&[0; 24])),
            ErrorCode::VerificationFailed,
            "other encrypted key",
        ),
    ] {
        assert_eq!(decrypt_compact(&token, key), Err(expected), "{what}");
    }
    assert_eq!(
        decrypt_compact(
            &handmade(&header("dir"), &[1; 16], None),
            DecryptionKey::Symmetric(&dir)
        ),
        Err(ErrorCode::Malformed),
        "dir with an encrypted key"
    );
    let mut small = interop();
    small.max_token_len = 100;
    assert_eq!(
        code(Jwe::parse(&token, &small, &Registry::standard())).map(|_| ()),
        Err(ErrorCode::TokenTooLarge)
    );
}

#[test]
fn keys_must_fit_the_token() {
    let a128kw = symmetric(A128KW_KEY);
    let dir = symmetric(DIR_KEY);
    let bob = bob();
    let kw_token = rfc7520("5.8 JWE Compact Serialization");
    let dir_token = rfc7520("5.6 JWE Compact Serialization");
    let ecdh_token = handmade(&appendix_c_header(), b"", None);
    let unbound = |bytes: Vec<u8>| SymmetricKey::new(bytes);
    for (token, key, what) in [
        (
            &kw_token,
            DecryptionKey::Agreement(&bob),
            "agreement key for A128KW",
        ),
        (
            &ecdh_token,
            DecryptionKey::Symmetric(&a128kw),
            "symmetric key for ECDH-ES",
        ),
        (
            &kw_token,
            DecryptionKey::Symmetric(&dir),
            "dir key (alg A128GCM) for A128KW",
        ),
        (
            &dir_token,
            DecryptionKey::Symmetric(&a128kw),
            "A128KW key for dir",
        ),
        (
            &kw_token,
            DecryptionKey::Symmetric(
                &unbound(vec![0; 32]).with_kid("81b20965-8332-43d9-a468-82160ad91ac8"),
            ),
            "32-byte key for A128KW",
        ),
        (
            &kw_token,
            DecryptionKey::Symmetric(&unbound(vec![0; 16]).with_kid("other")),
            "other kid",
        ),
    ] {
        assert_eq!(
            decrypt_compact(token, key),
            Err(ErrorCode::KeyMismatch),
            "{what}"
        );
    }
    assert_eq!(
        decrypt_compact(&kw_token, DecryptionKey::Symmetric(&unbound(vec![0; 16]))),
        Err(ErrorCode::VerificationFailed),
        "wrong A128KW key"
    );
}

const ALL_ALGS: [Alg; 8] = [
    Alg::DIR,
    Alg::A128KW,
    Alg::A192KW,
    Alg::A256KW,
    Alg::ECDH_ES,
    Alg::ECDH_ES_A128KW,
    Alg::ECDH_ES_A192KW,
    Alg::ECDH_ES_A256KW,
];
const ALL_ENCS: [Enc; 3] = [Enc::A128GCM, Enc::A192GCM, Enc::A256GCM];

#[test]
fn round_trip_every_alg_and_enc() {
    let registry = Registry::standard();
    let backend = backend();
    let recipient = SoftwareAgreementKey::generate(Curve::P256, backend.clone()).unwrap();
    let public = recipient.public_jwk();
    for alg in ALL_ALGS {
        for enc in ALL_ENCS {
            let len = match alg {
                a if a == Alg::DIR => registry.content_encryption(enc.as_str()).unwrap().key_len,
                a if a == Alg::A128KW => 16,
                a if a == Alg::A192KW => 24,
                a if a == Alg::A256KW => 32,
                _ => 0,
            };
            let shared = SymmetricKey::new((0..=u8::MAX).cycle().take(len).collect());
            let (encryption, decryption) = if len == 0 {
                (
                    EncryptionKey::Public(&public),
                    DecryptionKey::Agreement(&recipient),
                )
            } else {
                (
                    EncryptionKey::Symmetric(&shared),
                    DecryptionKey::Symmetric(&shared),
                )
            };
            // Plaintexts of every length up to two AES blocks and one longer one.
            for size in (0..=33).chain([1000]) {
                let plaintext: Vec<u8> = (0..=u8::MAX).cycle().step_by(7).take(size).collect();
                let token = jwe::encrypt(
                    &plaintext,
                    alg,
                    enc,
                    encryption,
                    HeaderParams::new()
                        .cty("x")
                        .param("apu", json!(b64(b"me")))
                        .unwrap(),
                    &registry,
                    backend.as_ref(),
                )
                .unwrap();
                let jwe = Jwe::parse(&token, &interop(), &registry).unwrap();
                assert_eq!(jwe.header().cty(), Some("x"));
                let decrypted = jwe.decrypt(decryption, backend.as_ref()).unwrap();
                assert_eq!(decrypted.plaintext(), plaintext, "{alg:?} {enc:?} {size}");
            }
        }
    }
}

#[test]
fn encryption_key_must_fit_the_algorithm() {
    let registry = Registry::standard();
    let backend = backend();
    let recipient = SoftwareAgreementKey::generate(Curve::P256, backend.clone()).unwrap();
    let mut signing_only = recipient.public_jwk();
    signing_only.key_use = Some("sig".into());
    let mut other_alg = recipient.public_jwk();
    other_alg.alg = Some("ECDH-ES+A128KW".into());
    let a128kw = symmetric(A128KW_KEY);
    let encrypt = |alg: Alg, key: EncryptionKey<'_>| {
        code(jwe::encrypt(
            b"x",
            alg,
            Enc::A128GCM,
            key,
            HeaderParams::new(),
            &registry,
            backend.as_ref(),
        ))
    };
    for (alg, key, expected) in [
        (
            Alg::ECDH_ES,
            EncryptionKey::Public(&signing_only),
            ErrorCode::KeyMismatch,
        ),
        (
            Alg::ECDH_ES,
            EncryptionKey::Public(&other_alg),
            ErrorCode::KeyMismatch,
        ),
        (
            Alg::ECDH_ES,
            EncryptionKey::Symmetric(&a128kw),
            ErrorCode::KeyMismatch,
        ),
        (
            Alg::A256KW,
            EncryptionKey::Symmetric(&a128kw),
            ErrorCode::KeyMismatch,
        ),
        (
            Alg::RSA_OAEP,
            EncryptionKey::Public(&signing_only),
            ErrorCode::UnsupportedAlgorithm,
        ),
    ] {
        assert_eq!(encrypt(alg, key).map(|_| ()), Err(expected), "{alg:?}");
    }
    assert_eq!(
        code(jwe::encrypt(
            b"x",
            Alg::ECDH_ES,
            Enc::A128CBC_HS256,
            EncryptionKey::Public(&recipient.public_jwk()),
            HeaderParams::new(),
            &registry,
            backend.as_ref(),
        ))
        .map(|_| ()),
        Err(ErrorCode::UnsupportedAlgorithm)
    );
    assert_eq!(
        code(HeaderParams::new().param("zip", json!("DEF"))).map(|_| ()),
        Err(ErrorCode::InvalidMember)
    );
}

#[test]
fn rfc_7516_7_2_1_general_json_with_several_recipients() {
    let registry = Registry::standard();
    let backend = backend();
    let first = SoftwareAgreementKey::generate(Curve::P256, backend.clone()).unwrap();
    let second = SoftwareAgreementKey::generate(Curve::P256, backend.clone()).unwrap();
    let mut first_public = first.public_jwk();
    first_public.kid = Some("first".into());
    let shared = symmetric(A128KW_KEY);
    let recipients = [
        Recipient {
            alg: Alg::ECDH_ES_A128KW,
            key: EncryptionKey::Public(&first_public),
            header: HeaderParams::new(),
        },
        Recipient {
            alg: Alg::ECDH_ES_A256KW,
            key: EncryptionKey::Public(&second.public_jwk()),
            header: HeaderParams::new().kid("second"),
        },
        Recipient {
            alg: Alg::A128KW,
            key: EncryptionKey::Symmetric(&shared),
            header: HeaderParams::new(),
        },
    ];
    let text = jwe::json::encrypt(
        b"to all",
        Enc::A256GCM,
        HeaderParams::new().typ("JWT"),
        &recipients,
        Some(b"context"),
        &registry,
        backend.as_ref(),
    )
    .unwrap();
    let parsed = jwe::json::parse(&text, &interop(), &registry).unwrap();
    let kids: Vec<_> = parsed
        .iter()
        .map(|j| j.header().kid().map(String::from))
        .collect();
    assert_eq!(
        kids,
        [
            Some("first".to_string()),
            Some("second".to_string()),
            Some("81b20965-8332-43d9-a468-82160ad91ac8".to_string())
        ]
    );
    let keys = [
        DecryptionKey::Agreement(&first),
        DecryptionKey::Agreement(&second),
        DecryptionKey::Symmetric(&shared),
    ];
    for (jwe, key) in parsed.into_iter().zip(keys) {
        assert_eq!(jwe.header().typ(), Some("JWT"));
        assert_eq!(
            jwe.decrypt(key, backend.as_ref()).unwrap().plaintext(),
            b"to all"
        );
    }

    // RFC 7518 §4.5, §4.6: a direct mode determines the CEK, so it cannot share one.
    let direct = [
        Recipient {
            alg: Alg::ECDH_ES,
            key: EncryptionKey::Public(&first_public),
            header: HeaderParams::new(),
        },
        recipients[2].clone(),
    ];
    assert_eq!(
        code(jwe::json::encrypt(
            b"x",
            Enc::A256GCM,
            HeaderParams::new(),
            &direct,
            None,
            &registry,
            backend.as_ref(),
        ))
        .map(|_| ()),
        Err(ErrorCode::InvalidMember)
    );
}

#[test]
fn json_headers_must_be_disjoint_and_enc_protected() {
    let key = symmetric(A128KW_KEY);
    let key = DecryptionKey::Symmetric(&key);
    let base: Value =
        serde_json::from_str(&rfc7520("5.11 Flattened JWE JSON Serialization")).unwrap();
    let mut duplicate = base.clone();
    duplicate["header"] = json!({"kid": "again"});
    duplicate["unprotected"]["kid"] = json!("81b20965-8332-43d9-a468-82160ad91ac8");
    let mut crit = base.clone();
    crit["unprotected"]["crit"] = json!(["x"]);
    let mut both = base.clone();
    both["recipients"] = json!([]);
    for (value, what) in [
        (duplicate, "kid twice"),
        (crit, "crit unprotected"),
        (both, "both serializations"),
    ] {
        assert_eq!(
            decrypt_json(&value.to_string(), key),
            Err(ErrorCode::Malformed),
            "{what}"
        );
    }
}

#[test]
fn decrypt_async_with_a_key_agreement() {
    let registry = Registry::standard();
    let backend = backend();
    let recipient = SoftwareAgreementKey::generate(Curve::P256, backend.clone()).unwrap();
    let token = jwe::encrypt(
        b"async",
        Alg::ECDH_ES_A128KW,
        Enc::A128GCM,
        EncryptionKey::Public(&recipient.public_jwk()),
        HeaderParams::new(),
        &registry,
        backend.as_ref(),
    )
    .unwrap();
    let jwe = Jwe::parse(&token, &interop(), &registry).unwrap();
    let decrypted =
        futures_lite::future::block_on(jwe.decrypt_async(&recipient, backend.as_ref())).unwrap();
    assert_eq!(decrypted.plaintext(), b"async");
}

/// P-256 ECDH under another curve name: a stand-in for a curve the base backend lacks.
struct Renamed {
    curve: Curve,
    base: Arc<RustCrypto>,
}

impl Ecdh for Renamed {
    fn curve(&self) -> Curve {
        self.curve
    }
    fn generate(&self, rng: &dyn Rng) -> Result<KeyPair, CryptoError> {
        self.base.ecdh(Curve::P256).unwrap().generate(rng)
    }
    fn agree(
        &self,
        secret: &[u8],
        peer: &[u8],
    ) -> Result<jwz::crypto::Zeroizing<Vec<u8>>, CryptoError> {
        self.base.ecdh(Curve::P256).unwrap().agree(secret, peer)
    }
}

#[test]
fn a_curve_added_through_the_extended_backend_works_end_to_end() {
    const TEST_CURVE: Curve = Curve::new("X-TEST-256");
    let mut registry = Registry::standard();
    registry
        .register_curve(CurveEntry {
            crv: TEST_CURVE,
            key_type: KeyType::EC,
            coordinate_len: 32,
            support: Support::Available,
        })
        .unwrap();
    let backend = Arc::new(
        Extended::new(RustCrypto::new()).with_ecdh(Box::new(Renamed {
            curve: TEST_CURVE,
            base: Arc::new(RustCrypto::new()),
        })),
    );
    let recipient = SoftwareAgreementKey::generate(TEST_CURVE, backend.clone()).unwrap();
    assert_eq!(recipient.public_jwk().crv(), Some("X-TEST-256"));
    let token = jwe::encrypt(
        b"extended",
        Alg::ECDH_ES,
        Enc::A128GCM,
        EncryptionKey::Public(&recipient.public_jwk()),
        HeaderParams::new(),
        &registry,
        backend.as_ref(),
    )
    .unwrap();
    let policy = Profile::rfc7518_interop(&registry).policy;
    let jwe = Jwe::parse(&token, &policy, &registry).unwrap();
    assert_eq!(
        jwe.header().epk().unwrap().unwrap().crv(),
        Some("X-TEST-256")
    );
    let decrypted = jwe
        .decrypt(DecryptionKey::Agreement(&recipient), backend.as_ref())
        .unwrap();
    assert_eq!(decrypted.plaintext(), b"extended");

    // The same P-256 recipient point under its real name is another curve: refused.
    let p256 = SoftwareAgreementKey::generate(Curve::P256, backend.clone()).unwrap();
    let jwe = Jwe::parse(&token, &policy, &registry).unwrap();
    assert_eq!(
        code(jwe.decrypt(DecryptionKey::Agreement(&p256), backend.as_ref())).map(|_| ()),
        Err(ErrorCode::KeyMismatch)
    );
}
