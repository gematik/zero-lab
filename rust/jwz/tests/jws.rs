//! JWS against RFC 7515 (A.1, A.3, A.7), RFC 7520 §4.4 and RFC 8037 A.4, the parsing
//! safety invariants (one test each), the negative matrix, the JSON serializations,
//! async signing through the KMS double and x5c handling.
#![cfg(all(feature = "crypto-rustcrypto", feature = "jws"))]

use std::sync::Arc;

use jwz::ErrorCode;
use jwz::crypto::Backend;
use jwz::crypto::rustcrypto::RustCrypto;
use jwz::header::HeaderParams;
use jwz::jwa::{HashAlgorithm, Registry, SignatureAlgorithm};
use jwz::jwk::Jwk;
use jwz::jws::{self, Jws};
use jwz::keys::SoftwareKey;
use jwz::profile::{Policy, Profile};

fn backend() -> Arc<RustCrypto> {
    Arc::new(RustCrypto::new())
}

fn strict() -> Policy {
    Profile::strict().policy
}

fn code<T>(r: Result<T, jwz::Error>) -> Result<T, ErrorCode> {
    r.map_err(|e| e.code())
}

const ES256_KEY: &str = r#"{"kty":"EC","crv":"P-256",
  "x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
  "y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
  "d":"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"}"#;
const RFC7515_A3: &str = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q";

fn es256_key() -> SoftwareKey<RustCrypto> {
    let jwk = Jwk::parse(ES256_KEY).unwrap();
    SoftwareKey::from_jwk(
        &jwk,
        SignatureAlgorithm::ES256,
        &Registry::standard(),
        backend(),
    )
    .unwrap()
}

#[test]
fn rfc_7515_a_3_es256_compact() {
    let registry = Registry::standard();
    let jws = Jws::parse(RFC7515_A3, &strict(), &registry).unwrap();
    assert_eq!(jws.algorithm(), SignatureAlgorithm::ES256);
    let verified = jws.verify(&es256_key()).unwrap();
    assert_eq!(
        verified.payload(),
        b"{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}"
    );
}

#[test]
fn rfc_8037_a_4_eddsa_compact() {
    let jwk = Jwk::parse(
        r#"{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#,
    )
    .unwrap();
    let registry = Registry::standard();
    let key = SoftwareKey::from_jwk(&jwk, SignatureAlgorithm::EDDSA, &registry, backend()).unwrap();
    let token = "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc.hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg";
    let verified = Jws::parse(token, &strict(), &registry)
        .unwrap()
        .verify(&key)
        .unwrap();
    assert_eq!(verified.payload(), b"Example of Ed25519 signing");
}

#[cfg(feature = "hmac")]
#[test]
fn rfc_7515_a_1_and_rfc_7520_4_4_hs256_under_the_interop_profile_only() {
    let registry = Registry::standard();
    let interop = Profile::rfc7518_interop(&registry).policy;
    for (key, token) in [
        (
            r#"{"kty":"oct","k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"}"#,
            "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
        ),
        (
            r#"{"kty":"oct","kid":"018c0ae5-4d9b-471b-bfd6-eef314bc7037","k":"hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg"}"#,
            "eyJhbGciOiJIUzI1NiIsImtpZCI6IjAxOGMwYWU1LTRkOWItNDcxYi1iZmQ2LWVlZjMxNGJjNzAzNyJ9.SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4.s0h6KThzkfBBBkLspW1h84VsJZFTsPPqMDA7g1Md7p0",
        ),
    ] {
        let jwk = Jwk::parse(key).unwrap();
        let key =
            SoftwareKey::from_jwk(&jwk, SignatureAlgorithm::HS256, &registry, backend()).unwrap();
        Jws::parse(token, &interop, &registry)
            .unwrap()
            .verify(&key)
            .unwrap();
        // The strict default refuses shared-secret JWS outright.
        assert_eq!(
            code(Jws::parse(token, &strict(), &registry)).err(),
            Some(ErrorCode::PolicyViolation)
        );
    }
}

#[test]
fn sign_and_verify_round_trip_with_kid_and_typ() {
    let registry = Registry::standard();
    let key = SoftwareKey::generate(SignatureAlgorithm::ES256, &registry, backend())
        .unwrap()
        .with_kid("key-1");
    let token = jws::sign(b"{}", HeaderParams::new().typ("JWT"), &key).unwrap();
    let parsed = Jws::parse(&token, &strict(), &registry).unwrap();
    assert_eq!(parsed.header().kid(), Some("key-1"));
    assert_eq!(parsed.header().typ(), Some("JWT"));
    assert_eq!(parsed.verify(&key).unwrap().payload(), b"{}");
}

// ---- parsing-safety invariants (ADR 0001, principle 5): one test each ----

#[test]
fn invariant_token_size_cap_before_decoding() {
    let mut policy = strict();
    policy.max_token_len = 32;
    let big = format!("{}.!!!.!!!", "A".repeat(64));
    assert_eq!(
        code(Jws::parse(&big, &policy, &Registry::standard())).err(),
        Some(ErrorCode::TokenTooLarge)
    );
}

#[test]
fn invariant_strict_base64url() {
    let registry = Registry::standard();
    let [h, p, s]: [&str; 3] = RFC7515_A3
        .split('.')
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    for token in [
        format!("{h}=.{p}.{s}"),
        format!("{h}.{p}=.{s}"),
        format!("{h}.{p}.{s}=="),
        format!("{h}.{p}.{}", s.replace('-', "+")),
    ] {
        assert_eq!(
            code(Jws::parse(&token, &strict(), &registry)).err(),
            Some(ErrorCode::Base64),
            "{token}"
        );
    }
}

#[test]
fn invariant_duplicate_header_members_rejected() {
    let header = jwz::b64::encode(br#"{"alg":"ES256","alg":"HS256"}"#);
    let token = format!("{header}.e30.AAAA");
    assert_eq!(
        code(Jws::parse(&token, &strict(), &Registry::standard())).err(),
        Some(ErrorCode::DuplicateMember)
    );
}

#[test]
fn invariant_crit_enforced() {
    let header = jwz::b64::encode(br#"{"alg":"ES256","crit":["exp"],"exp":1}"#);
    let token = format!("{header}.e30.AAAA");
    assert_eq!(
        code(Jws::parse(&token, &strict(), &Registry::standard())).err(),
        Some(ErrorCode::Critical)
    );
}

#[test]
fn invariant_none_unrepresentable() {
    for alg in ["none", "None", "NONE"] {
        let header = jwz::b64::encode(format!(r#"{{"alg":"{alg}"}}"#).as_bytes());
        let token = format!("{header}.e30.");
        let interop = Profile::rfc7518_interop(&Registry::standard()).policy;
        assert_eq!(
            code(Jws::parse(&token, &interop, &Registry::standard())).err(),
            Some(ErrorCode::UnsupportedAlgorithm),
            "{alg}"
        );
    }
}

#[test]
fn invariant_header_never_selects_the_algorithm() {
    // A valid ES256 key cannot verify a token the header says is EdDSA, even if the
    // signature bytes were right: the key's own algorithm decides.
    let registry = Registry::standard();
    let ed = SoftwareKey::generate(SignatureAlgorithm::EDDSA, &registry, backend()).unwrap();
    let token = jws::sign(b"x", HeaderParams::new(), &ed).unwrap();
    let parsed = Jws::parse(&token, &strict(), &registry).unwrap();
    assert_eq!(
        code(parsed.verify(&es256_key())).err(),
        Some(ErrorCode::KeyMismatch)
    );
}

// ---- negative matrix ----

#[test]
fn negative_altered_payload() {
    let [h, _, s]: [&str; 3] = RFC7515_A3
        .split('.')
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    let token = format!("{h}.{}.{s}", jwz::b64::encode(b"{\"iss\":\"eve\"}"));
    let parsed = Jws::parse(&token, &strict(), &Registry::standard()).unwrap();
    assert_eq!(
        code(parsed.verify(&es256_key())).err(),
        Some(ErrorCode::VerificationFailed)
    );
}

#[test]
fn negative_kid_mismatch() {
    let registry = Registry::standard();
    let key = SoftwareKey::generate(SignatureAlgorithm::ES256, &registry, backend())
        .unwrap()
        .with_kid("a");
    let token = jws::sign(b"x", HeaderParams::new().kid("b"), &key).unwrap();
    let parsed = Jws::parse(&token, &strict(), &registry).unwrap();
    assert_eq!(
        code(parsed.verify(&key)).err(),
        Some(ErrorCode::KeyMismatch)
    );
}

#[test]
fn negative_structure() {
    let registry = Registry::standard();
    for token in ["a.b", "a.b.c.d", "", "e30.e30.e30"] {
        let result = code(Jws::parse(token, &strict(), &registry)).err();
        assert!(
            matches!(
                result,
                Some(ErrorCode::Malformed | ErrorCode::Base64 | ErrorCode::MissingMember)
            ),
            "{token}: {result:?}"
        );
    }
    // A header that is JSON but not an object.
    let token = format!("{}.e30.AAAA", jwz::b64::encode(b"[1]"));
    assert_eq!(
        code(Jws::parse(&token, &strict(), &registry)).err(),
        Some(ErrorCode::Json)
    );
}

#[test]
fn negative_key_reference_without_opt_in() {
    let registry = Registry::standard();
    let key = SoftwareKey::generate(SignatureAlgorithm::ES256, &registry, backend()).unwrap();
    let token = jws::sign(
        b"x",
        HeaderParams::new().jwk(&key.public_jwk()).unwrap(),
        &key,
    )
    .unwrap();
    assert_eq!(
        code(Jws::parse(&token, &strict(), &registry)).err(),
        Some(ErrorCode::PolicyViolation)
    );
    // Opting in lets the header key be read; trusting it is the application's decision.
    let mut policy = strict();
    policy.key_references.jwk = true;
    let parsed = Jws::parse(&token, &policy, &registry).unwrap();
    let embedded = parsed.header().jwk().unwrap().unwrap();
    let verifier =
        SoftwareKey::from_jwk(&embedded, SignatureAlgorithm::ES256, &registry, backend()).unwrap();
    parsed.verify(&verifier).unwrap();
}

#[test]
fn header_params_refuse_what_jwz_sets_itself() {
    for name in ["alg", "enc", "crit"] {
        assert!(
            HeaderParams::new()
                .param(name, serde_json::json!("x"))
                .is_err(),
            "{name}"
        );
    }
    assert!(
        HeaderParams::new()
            .critical("alg", serde_json::json!(1))
            .is_err()
    );
    let registry = Registry::standard();
    let key = SoftwareKey::generate(SignatureAlgorithm::ES256, &registry, backend()).unwrap();
    assert!(
        HeaderParams::new().jwk(&key.to_jwk()).is_err(),
        "a private key must not be embedded"
    );
}

#[test]
fn understood_critical_extension_round_trip() {
    let registry = Registry::standard();
    let key = SoftwareKey::generate(SignatureAlgorithm::ES256, &registry, backend()).unwrap();
    let params = HeaderParams::new()
        .critical("urn:example:ext", serde_json::json!(true))
        .unwrap();
    let token = jws::sign(b"x", params, &key).unwrap();
    assert_eq!(
        code(Jws::parse(&token, &strict(), &registry)).err(),
        Some(ErrorCode::Critical)
    );
    let mut policy = strict();
    policy.understood_critical.push("urn:example:ext".into());
    Jws::parse(&token, &policy, &registry)
        .unwrap()
        .verify(&key)
        .unwrap();
}

// ---- JSON serialization (lightly) ----

const RFC7515_A7: &str = r#"{"payload":"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ","protected":"eyJhbGciOiJFUzI1NiJ9","header":{"kid":"e9bc097a-ce51-4036-9562-d2ade882db0d"},"signature":"DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"}"#;

#[test]
fn rfc_7515_a_7_flattened_json() {
    let registry = Registry::standard();
    let mut jws = jws::json::parse(RFC7515_A7, &strict(), &registry).unwrap();
    assert_eq!(jws.len(), 1);
    let jws = jws.pop().unwrap();
    assert_eq!(
        jws.header().kid(),
        Some("e9bc097a-ce51-4036-9562-d2ade882db0d")
    );
    // The key has no kid, so the unprotected kid does not get in the way.
    jws.verify(&es256_key()).unwrap();
}

#[test]
fn json_alg_must_be_protected_and_headers_disjoint() {
    let registry = Registry::standard();
    for text in [
        r#"{"payload":"e30","protected":"e30","header":{"alg":"ES256"},"signature":"AA"}"#,
        r#"{"payload":"e30","protected":"eyJhbGciOiJFUzI1NiJ9","header":{"alg":"ES256"},"signature":"AA"}"#,
        r#"{"payload":"e30","header":{"alg":"ES256"},"signature":"AA"}"#,
        r#"{"payload":"e30","signatures":[]}"#,
    ] {
        assert_eq!(
            code(jws::json::parse(text, &strict(), &registry)).err(),
            Some(ErrorCode::Malformed),
            "{text}"
        );
    }
}

#[test]
fn general_json_with_two_signers() {
    let registry = Registry::standard();
    let es = SoftwareKey::generate(SignatureAlgorithm::ES256, &registry, backend()).unwrap();
    let ed = SoftwareKey::generate(SignatureAlgorithm::EDDSA, &registry, backend()).unwrap();
    let text = jws::json::sign(
        b"both",
        &[(&es, HeaderParams::new()), (&ed, HeaderParams::new())],
    )
    .unwrap();
    let mut parsed = jws::json::parse(&text, &strict(), &registry).unwrap();
    let second = parsed.pop().unwrap();
    let first = parsed.pop().unwrap();
    assert_eq!(first.verify(&es).unwrap().payload(), b"both");
    assert_eq!(second.verify(&ed).unwrap().payload(), b"both");
}

// ---- async signing and x5c ----

#[cfg(feature = "test-util")]
#[test]
fn sign_async_through_the_kms_double_verifies_synchronously() {
    use futures_lite::future;
    use jwz::keys::TestKms;
    let registry = Registry::standard();
    let key = SoftwareKey::generate(SignatureAlgorithm::ES256, &registry, backend()).unwrap();
    let (kms, signer) = TestKms::new(key);
    let mut signing = Box::pin(jws::sign_async(b"remote", HeaderParams::new(), &signer));
    assert!(
        future::block_on(future::poll_once(&mut signing)).is_none(),
        "waits for the KMS"
    );
    kms.serve();
    let token = future::block_on(signing).unwrap();
    let verifier = SoftwareKey::from_jwk(
        &kms.public_jwk(),
        SignatureAlgorithm::ES256,
        &registry,
        backend(),
    )
    .unwrap();
    let parsed = Jws::parse(&token, &strict(), &registry).unwrap();
    assert_eq!(
        future::block_on(parsed.verify_async(&verifier))
            .unwrap()
            .payload(),
        b"remote"
    );
}

#[test]
fn rfc_7515_4_1_8_x5t_s256_binds_the_leaf() {
    let registry = Registry::standard();
    let backend = backend();
    let sha256 = backend.hash(HashAlgorithm::Sha256).unwrap();
    let key =
        SoftwareKey::generate(SignatureAlgorithm::ES256, &registry, Arc::clone(&backend)).unwrap();
    let leaf: &[u8] = b"leaf certificate DER";
    let thumbprint = jwz::b64::encode(&sha256.digest(&[leaf]));
    let mut policy = strict();
    policy.key_references.x5c = true;
    for (x5t, ok) in [(thumbprint.as_str(), true), ("AAAA", false)] {
        let params = HeaderParams::new()
            .x5c(&[leaf, b"ca"])
            .param("x5t#S256", serde_json::json!(x5t))
            .unwrap();
        let token = jws::sign(b"x", params, &key).unwrap();
        let parsed = Jws::parse(&token, &policy, &registry).unwrap();
        let chain = jwz::x5c::chain(parsed.header(), sha256);
        assert_eq!(chain.is_ok(), ok, "{x5t}");
        if ok {
            assert_eq!(chain.unwrap(), vec![leaf.to_vec(), b"ca".to_vec()]);
        }
    }
}
