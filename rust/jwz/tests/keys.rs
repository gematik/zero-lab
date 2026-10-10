//! JWK and keys against the RFC examples (RFC 7515 A.1/A.3, RFC 7517 A, RFC 7638 §3.1,
//! RFC 8037 A), the key-binding rules, and the HSM and KMS seams.
#![cfg(feature = "crypto-rustcrypto")]

use std::sync::Arc;

use jwz::ErrorCode;
use jwz::crypto::Backend;
use jwz::crypto::rustcrypto::RustCrypto;
use jwz::jwa::{HashAlgorithm, Registry, SignatureAlgorithm};
use jwz::jwk::{Jwk, JwkSet, KeyMaterial};
use jwz::keys::{KeyAgreement, Signature, SoftwareAgreementKey, SoftwareKey, Verifier};

fn backend() -> Arc<RustCrypto> {
    Arc::new(RustCrypto::new())
}

fn b64(s: &str) -> Vec<u8> {
    jwz::b64::decode(s, "test").unwrap()
}

const RFC7517_A1: &str = r#"{"keys":[
  {"kty":"EC","crv":"P-256",
   "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
   "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
   "use":"enc","kid":"1"},
  {"kty":"RSA",
   "n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
   "e":"AQAB","alg":"RS256","kid":"2011-04-29"}]}"#;

#[test]
fn rfc_7517_a_1_public_key_set() {
    let set = JwkSet::parse(RFC7517_A1).unwrap();
    assert_eq!(set.keys.len(), 2);
    let registry = Registry::standard();
    for key in &set.keys {
        key.check(&registry).unwrap();
        assert!(!key.is_private());
    }
    assert_eq!(set.by_kid("1").count(), 1);
    assert_eq!(set.keys[0].key_use.as_deref(), Some("enc"));
}

#[test]
fn rfc_7638_3_1_thumbprint_of_the_rsa_example() {
    let set = JwkSet::parse(RFC7517_A1).unwrap();
    let hash = backend();
    let sha256 = hash.hash(HashAlgorithm::Sha256).unwrap();
    assert_eq!(
        set.keys[1].thumbprint(sha256),
        "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
    );
}

const RFC8037_A1: &str = r#"{"kty":"OKP","crv":"Ed25519",
  "d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",
  "x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#;

#[test]
fn rfc_8037_a_3_thumbprint_and_a_4_signature() {
    let jwk = Jwk::parse(RFC8037_A1).unwrap();
    let backend = backend();
    let sha256 = backend.hash(HashAlgorithm::Sha256).unwrap();
    assert_eq!(
        jwk.thumbprint(sha256),
        "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
    );
    let key = SoftwareKey::from_jwk(
        &jwk,
        SignatureAlgorithm::EDDSA,
        &Registry::standard(),
        backend,
    )
    .unwrap();
    let input = b"eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc";
    let expected = b64(
        "hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg",
    );
    // Ed25519 is deterministic: the signature must be the RFC's exactly.
    assert_eq!(
        jwz::keys::Signer::try_sign(&key, input).unwrap().as_bytes(),
        expected
    );
    key.verify(input, &Signature::from(expected)).unwrap();
}

const RFC7515_A3_KEY: &str = r#"{"kty":"EC","crv":"P-256",
  "x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
  "y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
  "d":"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"}"#;
const RFC7515_A3_INPUT: &[u8] = b"eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ";
const RFC7515_A3_SIG: &str =
    "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q";

#[test]
fn rfc_7515_a_3_es256_signature_verifies_and_a_tampered_one_does_not() {
    let jwk = Jwk::parse(RFC7515_A3_KEY).unwrap();
    let key = SoftwareKey::from_jwk(
        &jwk.public(),
        SignatureAlgorithm::ES256,
        &Registry::standard(),
        backend(),
    )
    .unwrap();
    let sig = b64(RFC7515_A3_SIG);
    key.verify(RFC7515_A3_INPUT, &Signature::from(sig.clone()))
        .unwrap();
    let mut tampered = sig;
    tampered[10] ^= 1;
    assert_eq!(
        key.verify(RFC7515_A3_INPUT, &Signature::from(tampered))
            .map_err(|e| e.code()),
        Err(ErrorCode::VerificationFailed)
    );
}

#[cfg(feature = "hmac")]
#[test]
fn rfc_7515_a_1_hs256_signature() {
    let jwk = Jwk::parse(
        r#"{"kty":"oct","k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"}"#,
    )
    .unwrap();
    let key = SoftwareKey::from_jwk(
        &jwk,
        SignatureAlgorithm::HS256,
        &Registry::standard(),
        backend(),
    )
    .unwrap();
    let input = b"eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ";
    assert_eq!(
        jwz::keys::Signer::try_sign(&key, input).unwrap().as_bytes(),
        b64("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
    );
}

#[cfg(feature = "hmac")]
#[test]
fn rfc_7518_3_2_hmac_key_shorter_than_the_hash_is_refused() {
    let jwk = Jwk::parse(r#"{"kty":"oct","k":"AAECAwQFBgcICQoLDA0ODw"}"#).unwrap();
    assert_eq!(
        SoftwareKey::from_jwk(
            &jwk,
            SignatureAlgorithm::HS256,
            &Registry::standard(),
            backend()
        )
        .map(|_| ())
        .map_err(|e| e.code()),
        Err(ErrorCode::KeyLength)
    );
}

#[test]
fn rfc_7517_4_4_a_key_is_bound_to_its_algorithm() {
    let registry = Registry::standard();
    let ec = Jwk::parse(RFC7515_A3_KEY).unwrap();
    // The RFC's private key belongs to its public key and loads.
    SoftwareKey::from_jwk(&ec, SignatureAlgorithm::ES256, &registry, backend()).unwrap();
    let err = |jwk: &Jwk, alg| {
        SoftwareKey::from_jwk(jwk, alg, &registry, backend())
            .map(|_| ())
            .map_err(|e| e.code())
    };
    // An EC key is not an EdDSA key, and reserved algorithms are refused.
    assert_eq!(
        err(&ec, SignatureAlgorithm::EDDSA),
        Err(ErrorCode::KeyMismatch)
    );
    assert_eq!(
        err(&ec, SignatureAlgorithm::ES384),
        Err(ErrorCode::UnsupportedAlgorithm)
    );
    // The key's own alg wins over the caller's.
    let mut named = ec.clone();
    named.alg = Some("ES384".into());
    assert_eq!(
        err(&named, SignatureAlgorithm::ES256),
        Err(ErrorCode::KeyMismatch)
    );
    // A private part that does not belong to the public part.
    let mut forged = ec;
    if let KeyMaterial::Ec(k) = &mut forged.material {
        k.x[0] ^= 1;
    }
    assert_eq!(
        err(&forged, SignatureAlgorithm::ES256),
        Err(ErrorCode::KeyMismatch)
    );
}

#[test]
fn rfc_7518_6_2_1_2_coordinates_have_the_full_length() {
    let short = r#"{"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7A","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"}"#;
    let jwk = Jwk::parse(short).unwrap();
    assert_eq!(
        jwk.check(&Registry::standard()).map_err(|e| e.code()),
        Err(ErrorCode::KeyLength)
    );
    let unknown = r#"{"kty":"EC","crv":"P-257","x":"AA","y":"AA"}"#;
    assert_eq!(
        Jwk::parse(unknown)
            .unwrap()
            .check(&Registry::standard())
            .map_err(|e| e.code()),
        Err(ErrorCode::UnknownCurve)
    );
}

#[test]
fn jwk_parsing_is_strict() {
    for (text, code) in [
        (
            r#"{"kty":"EC","kty":"EC","crv":"P-256","x":"AA","y":"AA"}"#,
            ErrorCode::DuplicateMember,
        ),
        (
            r#"{"kty":"EC","crv":"P-256","x":"AA==","y":"AA"}"#,
            ErrorCode::Base64,
        ),
        (
            r#"{"kty":"EC","crv":"P-256","y":"AA"}"#,
            ErrorCode::MissingMember,
        ),
        (
            r#"{"kty":"EC","crv":7,"x":"AA","y":"AA"}"#,
            ErrorCode::InvalidMember,
        ),
        (r#"{"kty":"XYZ"}"#, ErrorCode::UnsupportedKeyType),
    ] {
        assert_eq!(Jwk::parse(text).map_err(|e| e.code()), Err(code), "{text}");
    }
    // A set skips key types it does not know (RFC 7517 §5) but not broken keys.
    let set = JwkSet::parse(r#"{"keys":[{"kty":"XYZ"},{"kty":"oct","k":"AQ"}]}"#).unwrap();
    assert_eq!(set.keys.len(), 1);
}

#[test]
fn private_material_never_shows_in_debug_output() {
    let jwk = Jwk::parse(RFC7515_A3_KEY).unwrap();
    let debug = format!("{jwk:?}");
    assert!(debug.contains("Secret(..)"));
    assert!(!debug.contains("142, 155"), "{debug}");
}

#[test]
fn generated_keys_round_trip_through_their_jwk() {
    let registry = Registry::standard();
    for alg in [SignatureAlgorithm::ES256, SignatureAlgorithm::EDDSA] {
        let key = SoftwareKey::generate(alg, &registry, backend())
            .unwrap()
            .with_kid("k1");
        let sig = jwz::keys::Signer::try_sign(&key, b"msg").unwrap();
        let public = key.public_jwk();
        assert!(!public.is_private());
        let parsed = Jwk::parse(&public.to_json()).unwrap();
        assert_eq!(parsed, public);
        let verifier = SoftwareKey::from_jwk(&parsed, alg, &registry, backend()).unwrap();
        verifier.verify(b"msg", &sig).unwrap();
        assert_eq!(
            verifier.verify(b"other", &sig).map_err(|e| e.code()),
            Err(ErrorCode::VerificationFailed)
        );
        assert_eq!(jwz::keys::JwsKey::key_id(&verifier), Some("k1"));
        // A public key cannot sign.
        assert_eq!(
            jwz::keys::Signer::try_sign(&verifier, b"msg").map_err(|e| e.code()),
            Err(ErrorCode::MissingPrivateKey)
        );
    }
}

#[test]
fn ecdh_both_sides_agree() {
    let alice = SoftwareAgreementKey::generate(jwz::jwa::Curve::P256, backend()).unwrap();
    let bob = SoftwareAgreementKey::generate(jwz::jwa::Curve::P256, backend()).unwrap();
    let point = |jwk: Jwk| match jwk.material {
        KeyMaterial::Ec(k) => [vec![4], k.x, k.y].concat(),
        _ => unreachable!(),
    };
    let z1 = alice.agree(&point(bob.public_jwk())).unwrap();
    let z2 = bob.agree(&point(alice.public_jwk())).unwrap();
    assert_eq!(*z1, *z2);
    assert_eq!(z1.len(), 32);
}

#[cfg(feature = "test-util")]
mod seams {
    use super::*;
    use futures_lite::future;
    use jwz::keys::{AsyncSigner, FixedRng, MockHsm, TestKms};

    #[test]
    fn mock_hsm_signer_holds_only_a_handle() {
        let registry = Registry::standard();
        let hsm = MockHsm::new(backend());
        let signer = hsm.generate(SignatureAlgorithm::ES256, &registry).unwrap();
        assert_eq!(signer.handle(), 0);
        let sig = jwz::keys::Signer::try_sign(&signer, b"msg").unwrap();
        let public = signer.public_jwk().unwrap();
        assert!(!public.is_private());
        SoftwareKey::from_jwk(&public, SignatureAlgorithm::ES256, &registry, backend())
            .unwrap()
            .verify(b"msg", &sig)
            .unwrap();
    }

    #[test]
    fn test_kms_signer_is_pending_until_the_kms_answers() {
        let registry = Registry::standard();
        let rng = Box::new(FixedRng::new(7));
        let backend = Arc::new(RustCrypto::with_rng(rng));
        let key = SoftwareKey::generate(SignatureAlgorithm::ES256, &registry, Arc::clone(&backend))
            .unwrap();
        let (kms, signer) = TestKms::new(key);
        let mut signing = signer.sign_async(b"msg");
        assert!(future::block_on(future::poll_once(&mut signing)).is_none());
        assert_eq!(kms.serve(), 1);
        let sig = future::block_on(signing).unwrap();
        SoftwareKey::from_jwk(
            &kms.public_jwk(),
            SignatureAlgorithm::ES256,
            &registry,
            backend,
        )
        .unwrap()
        .verify(b"msg", &sig)
        .unwrap();
    }

    #[test]
    fn fixed_rng_makes_generation_reproducible() {
        let registry = Registry::standard();
        let make = || {
            let backend = Arc::new(RustCrypto::with_rng(Box::new(FixedRng::new(42))));
            SoftwareKey::generate(SignatureAlgorithm::EDDSA, &registry, backend)
                .unwrap()
                .public_jwk()
        };
        assert_eq!(make(), make());
    }
}
