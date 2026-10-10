//! The default backend in a browser: wasm32-unknown-unknown in headless Chrome, random
//! numbers from `Crypto.getRandomValues`. Known answers from RFC 7515, RFC 8037 and
//! RFC 7520 show the arithmetic is the native one; round trips cover key generation,
//! JWS and JWE end to end. Design time (`just jwz-browser`, stamped): the browser and
//! its driver are not needed by `just check`.
#![cfg(all(
    target_family = "wasm",
    target_os = "unknown",
    feature = "crypto-rustcrypto",
    feature = "jws",
    feature = "jwe",
    feature = "jwt"
))]

use std::sync::Arc;

use jwz::crypto::rustcrypto::RustCrypto;
use jwz::header::HeaderParams;
use jwz::jwa::{
    ContentEncryptionAlgorithm as Enc, Curve, KeyEncryptionAlgorithm as Alg, Registry,
    SignatureAlgorithm,
};
use jwz::jwe::{self, DecryptionKey, EncryptionKey, Jwe};
use jwz::jwk::Jwk;
use jwz::jws::{self, Jws};
use jwz::jwt::{Claims, FixedClock};
use jwz::keys::{SoftwareAgreementKey, SoftwareKey, SymmetricKey};
use jwz::profile::Profile;
use serde_json::Value;
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

wasm_bindgen_test_configure!(run_in_browser);

fn backend() -> Arc<RustCrypto> {
    Arc::new(RustCrypto::new())
}

/// RFC 7515 Appendix A.3.
const ES256_KEY: &str = r#"{"kty":"EC","crv":"P-256",
  "x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
  "y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}"#;
const RFC7515_A3: &str = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q";

/// RFC 8037 Appendix A.4.
const ED25519_KEY: &str =
    r#"{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#;
const RFC8037_A4: &str = "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc.hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg";

/// RFC 7520 §5.8, Figure 151.
const A128KW_KEY: &str = r#"{"kty":"oct","kid":"81b20965-8332-43d9-a468-82160ad91ac8",
  "use":"enc","alg":"A128KW","k":"GZy6sIZ6wl9NJOKB-jnmVQ"}"#;

#[wasm_bindgen_test]
fn rfc_7515_a_3_es256() {
    let registry = Registry::standard();
    let jwk = Jwk::parse(ES256_KEY).unwrap();
    let key = SoftwareKey::from_jwk(&jwk, SignatureAlgorithm::ES256, &registry, backend()).unwrap();
    let jws = Jws::parse(RFC7515_A3, &Profile::strict().policy, &registry).unwrap();
    let verified = jws.verify(&key).unwrap();
    assert!(verified.payload().starts_with(b"{\"iss\":\"joe\""));
}

#[wasm_bindgen_test]
fn rfc_8037_a_4_eddsa() {
    let registry = Registry::standard();
    let jwk = Jwk::parse(ED25519_KEY).unwrap();
    let key = SoftwareKey::from_jwk(&jwk, SignatureAlgorithm::EDDSA, &registry, backend()).unwrap();
    let jws = Jws::parse(RFC8037_A4, &Profile::strict().policy, &registry).unwrap();
    assert_eq!(
        jws.verify(&key).unwrap().payload(),
        b"Example of Ed25519 signing"
    );
}

#[wasm_bindgen_test]
fn rfc_7520_5_8_a128kw_a128gcm() {
    let registry = Registry::standard();
    let all: serde_json::Map<String, Value> =
        serde_json::from_str(include_str!("data/rfc7520/jwe.json")).unwrap();
    let token = all["5.8 JWE Compact Serialization"].as_str().unwrap();
    let key = SymmetricKey::from_jwk(&Jwk::parse(A128KW_KEY).unwrap(), &registry).unwrap();
    let policy = Profile::rfc7518_interop(&registry).policy;
    let decrypted = Jwe::parse(token, &policy, &registry)
        .unwrap()
        .decrypt(DecryptionKey::Symmetric(&key), backend().as_ref())
        .unwrap();
    assert!(
        decrypted
            .plaintext()
            .starts_with(b"You can trust us to stick with you")
    );
}

#[wasm_bindgen_test]
fn generated_keys_sign_and_verify() {
    let registry = Registry::standard();
    for alg in [SignatureAlgorithm::ES256, SignatureAlgorithm::EDDSA] {
        let key = SoftwareKey::generate(alg, &registry, backend()).unwrap();
        let other = SoftwareKey::generate(alg, &registry, backend()).unwrap();
        // Two keys from Crypto.getRandomValues: a stuck random source would repeat.
        assert_ne!(key.public_jwk(), other.public_jwk(), "{alg:?}");
        let token = jws::sign(b"{}", HeaderParams::new().typ("JWT"), &key).unwrap();
        let jws = Jws::parse(&token, &Profile::strict().policy, &registry).unwrap();
        assert_eq!(jws.verify(&key).unwrap().payload(), b"{}", "{alg:?}");
        let jws = Jws::parse(&token, &Profile::strict().policy, &registry).unwrap();
        assert!(jws.verify(&other).is_err(), "{alg:?}");
    }
}

#[wasm_bindgen_test]
fn ecdh_es_and_key_wrap_round_trip() {
    let registry = Registry::standard();
    let backend = backend();
    let policy = Profile::rfc7518_interop(&registry).policy;
    let recipient = SoftwareAgreementKey::generate(Curve::P256, backend.clone()).unwrap();
    let public = recipient.public_jwk();
    let shared = SymmetricKey::new((0..32).collect());
    for (alg, encryption, decryption) in [
        (
            Alg::ECDH_ES,
            EncryptionKey::Public(&public),
            DecryptionKey::Agreement(&recipient),
        ),
        (
            Alg::ECDH_ES_A256KW,
            EncryptionKey::Public(&public),
            DecryptionKey::Agreement(&recipient),
        ),
        (
            Alg::A256KW,
            EncryptionKey::Symmetric(&shared),
            DecryptionKey::Symmetric(&shared),
        ),
    ] {
        let token = jwe::encrypt(
            b"in the browser",
            alg,
            Enc::A256GCM,
            encryption,
            HeaderParams::new(),
            &registry,
            backend.as_ref(),
        )
        .unwrap();
        let decrypted = Jwe::parse(&token, &policy, &registry)
            .unwrap()
            .decrypt(decryption, backend.as_ref())
            .unwrap();
        assert_eq!(decrypted.plaintext(), b"in the browser", "{alg:?}");
    }
}

#[wasm_bindgen_test]
fn claims_with_a_caller_clock() {
    let claims = Claims::parse(br#"{"iss":"https://idp","exp":1000}"#).unwrap();
    claims
        .validate(&Profile::strict().claims, &FixedClock(900))
        .unwrap();
    assert!(
        claims
            .validate(&Profile::strict().claims, &FixedClock(2000))
            .is_err()
    );
}
