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

//! JWS against RFC 7515 (A.1, A.3, A.7), RFC 7520 §4.4 and RFC 8037 A.4, the parsing
//! safety invariants (one test each), the negative matrix, the JSON serializations,
//! async signing through the KMS double and x5c handling.
#![cfg(all(feature = "crypto-rustcrypto", feature = "jws"))]

use std::sync::Arc;

use jwz::ErrorCode;
use jwz::crypto::Backend;
use jwz::crypto::rustcrypto::RustCrypto;
use jwz::header::HeaderParams;
use jwz::jwa::{Curve, HashAlgorithm, Registry, SignatureAlgorithm};
use jwz::jwk::Jwk;
use jwz::jws::{self, Jws};
use jwz::keys::{JwsKey, Signature, SoftwareKey};
#[cfg(feature = "hmac")]
use jwz::profile::HMAC;
use jwz::profile::{ECDSA_NIST, Policy, Profile};

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
    let token = jws::sign(
        b"{}",
        HeaderParams::new().typ("JWT"),
        &key,
        &strict(),
        &registry,
    )
    .unwrap();
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
    let token = jws::sign(b"x", HeaderParams::new(), &ed, &strict(), &registry).unwrap();
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
    let token = jws::sign(
        b"x",
        HeaderParams::new().kid("b"),
        &key,
        &strict(),
        &registry,
    )
    .unwrap();
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
        &strict(),
        &registry,
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
    let token = jws::sign(b"x", params, &key, &strict(), &registry).unwrap();
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
fn rfc_7515_7_2_1_alg_protected_and_headers_disjoint() {
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
fn rfc_7515_7_2_1_general_json_with_two_signers() {
    let registry = Registry::standard();
    let es = SoftwareKey::generate(SignatureAlgorithm::ES256, &registry, backend()).unwrap();
    let ed = SoftwareKey::generate(SignatureAlgorithm::EDDSA, &registry, backend()).unwrap();
    let text = jws::json::sign(
        b"both",
        &[(&es, HeaderParams::new()), (&ed, HeaderParams::new())],
        &strict(),
        &registry,
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
    let policy = strict();
    let mut signing = Box::pin(jws::sign_async(
        b"remote",
        HeaderParams::new(),
        &signer,
        &policy,
        &registry,
    ));
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
        let token = jws::sign(b"x", params, &key, &strict(), &registry).unwrap();
        let parsed = Jws::parse(&token, &policy, &registry).unwrap();
        let chain = jwz::x5c::chain(parsed.header(), sha256);
        assert_eq!(chain.is_ok(), ok, "{x5t}");
        if ok {
            assert_eq!(chain.unwrap(), vec![leaf.to_vec(), b"ca".to_vec()]);
        }
    }
}

// ---- header parameters and the signing input ----

#[test]
fn rfc_7515_4_1_1_alg_is_required_and_case_sensitive() {
    let registry = Registry::standard();
    for (header, expected) in [
        (r#"{"kid":"k"}"#, ErrorCode::MissingMember),
        (r#"{"alg":"es256"}"#, ErrorCode::UnsupportedAlgorithm),
        (r#"{"alg":"Es256"}"#, ErrorCode::UnsupportedAlgorithm),
        (r#"{"alg":["ES256"]}"#, ErrorCode::MissingMember),
    ] {
        let token = format!("{}.e30.AAAA", jwz::b64::encode(header.as_bytes()));
        assert_eq!(
            code(Jws::parse(&token, &strict(), &registry)).err(),
            Some(expected),
            "{header}"
        );
    }
}

/// `x5c` entries are standard base64 with padding, not base64url, and the chain is not
/// empty.
#[test]
fn rfc_7515_4_1_6_x5c_is_padded_standard_base64() {
    let der: &[u8] = &[0xfb, 0xff, 0xbf];
    let header = |x5c: serde_json::Value| {
        let json = serde_json::json!({ "alg": "ES256", "x5c": x5c }).to_string();
        jwz::header::Header::decode(&jwz::b64::encode(json.as_bytes())).unwrap()
    };
    assert_eq!(
        header(serde_json::json!(["+/+/", "AQ=="]))
            .x5c()
            .unwrap()
            .unwrap(),
        vec![der.to_vec(), vec![1]]
    );
    let token = jws::sign(
        b"x",
        HeaderParams::new().x5c(&[der]),
        &es256_key(),
        &strict(),
        &Registry::standard(),
    )
    .unwrap();
    let mut policy = strict();
    policy.key_references.x5c = true;
    let parsed = Jws::parse(&token, &policy, &Registry::standard()).unwrap();
    assert_eq!(
        parsed.header().get("x5c"),
        Some(&serde_json::json!(["+/+/"]))
    );
    for (x5c, expected) in [
        (serde_json::json!(["-_-_"]), ErrorCode::Base64),
        (serde_json::json!(["AQ"]), ErrorCode::Base64),
        (serde_json::json!([]), ErrorCode::InvalidMember),
        (serde_json::json!("AQ=="), ErrorCode::InvalidMember),
    ] {
        assert_eq!(
            header(x5c.clone()).x5c().map_err(|e| e.code()).err(),
            Some(expected),
            "{x5c}"
        );
    }
}

/// The signature covers ASCII(BASE64URL(protected header) || '.' || BASE64URL(payload)),
/// so it verifies over exactly those bytes and over nothing else.
#[test]
fn rfc_7515_5_1_the_signing_input_is_header_dot_payload() {
    use jwz::keys::{Signature, Verifier};
    let key = es256_key();
    let token = jws::sign(
        b"{\"a\":1}",
        HeaderParams::new().kid("k"),
        &key,
        &strict(),
        &Registry::standard(),
    )
    .unwrap();
    let [h, p, s]: [&str; 3] = token.split('.').collect::<Vec<_>>().try_into().unwrap();
    assert_eq!(p, jwz::b64::encode(b"{\"a\":1}"));
    let signature = Signature::from(jwz::b64::decode(s, "signature").unwrap());
    key.verify(format!("{h}.{p}").as_bytes(), &signature)
        .unwrap();
    for other in [format!("{h}{p}"), format!("{h}.{p}."), format!(".{p}")] {
        assert!(key.verify(other.as_bytes(), &signature).is_err(), "{other}");
    }
}

/// RFC 4648 §5: `-` and `_` in place of `+` and `/`; the standard alphabet is refused
/// in a token.
#[test]
fn rfc_4648_5_base64url_alphabet() {
    let bytes = [0xfb, 0xff, 0xbf];
    assert_eq!(jwz::b64::encode(&bytes), "-_-_");
    assert_eq!(jwz::b64::decode("-_-_", "test").unwrap(), bytes);
    for text in ["+/+/", "-_-/", "+_-_"] {
        assert_eq!(
            jwz::b64::decode(text, "test").map_err(|e| e.code()),
            Err(ErrorCode::Base64),
            "{text}"
        );
    }
}

/// RFC 7797 makes `b64` change the signing input, and jwz does not implement it: a
/// token carrying `b64` is refused, critical and understood or not.
#[test]
fn rfc_7797_3_b64_is_refused() {
    let registry = Registry::standard();
    let key = es256_key();
    let mut understood = strict();
    understood.understood_critical.push("b64".into());
    for (params, policy) in [
        (
            HeaderParams::new()
                .param("b64", serde_json::json!(false))
                .unwrap(),
            strict(),
        ),
        (
            HeaderParams::new()
                .critical("b64", serde_json::json!(false))
                .unwrap(),
            understood.clone(),
        ),
        (
            HeaderParams::new()
                .critical("b64", serde_json::json!(true))
                .unwrap(),
            understood,
        ),
    ] {
        let token = jws::sign(b"x", params, &key, &strict(), &registry).unwrap();
        assert_eq!(
            code(Jws::parse(&token, &policy, &registry)).err(),
            Some(ErrorCode::PolicyViolation)
        );
    }
}

/// A resolver that offers fixed keys, or fails.
struct Offered(Result<Vec<Jwk>, jwz::Error>);

impl jwz::jwk::KeyResolver for Offered {
    fn resolve(
        &self,
        _header: &jwz::header::Header,
        _alg: SignatureAlgorithm,
    ) -> Result<Vec<Jwk>, jwz::Error> {
        self.0.clone()
    }
}

impl jwz::jwk::AsyncKeyResolver for Offered {
    fn resolve_async<'a>(
        &'a self,
        header: &'a jwz::header::Header,
        alg: SignatureAlgorithm,
    ) -> jwz::crypto::asynchronous::BoxFuture<'a, Result<Vec<Jwk>, jwz::Error>> {
        let keys = jwz::jwk::KeyResolver::resolve(self, header, alg);
        Box::pin(async move { keys })
    }
}

fn generated(kid: &str) -> SoftwareKey<RustCrypto> {
    SoftwareKey::generate(SignatureAlgorithm::ES256, &Registry::standard(), backend())
        .unwrap()
        .with_kid(kid)
}

/// RFC 7515 §5.2 step 8 with resolved keys: each candidate the resolver offers is tried,
/// one that does not fit the algorithm is passed over, and the JWS verifies only if a
/// candidate's signature check succeeds. Being offered is no trust: a resolver that offers
/// the wrong keys, or none, gets `VerificationFailed`, and its own failure is passed on.
#[test]
fn rfc_7515_5_2_step_8_resolved_keys_are_candidates_the_signature_decides() {
    let registry = Registry::standard();
    let (signer, other) = (generated("k1"), generated("k2"));
    let token = jws::sign(b"hello", HeaderParams::new(), &signer, &strict(), &registry).unwrap();
    let verify = |offered: Offered| {
        code(
            Jws::parse(&token, &strict(), &registry)
                .unwrap()
                .verify_with(&offered, &registry, &backend())
                .map(Jws::into_payload),
        )
    };
    let okp = Jwk::parse(
        r#"{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#,
    )
    .unwrap();
    // The signer's key among others, after one of another type, verifies.
    assert_eq!(
        verify(Offered(Ok(vec![
            okp.clone(),
            other.public_jwk(),
            signer.public_jwk()
        ]))),
        Ok(b"hello".to_vec())
    );
    // Only keys that do not verify, or none: refused.
    assert_eq!(
        verify(Offered(Ok(vec![okp, other.public_jwk()]))),
        Err(ErrorCode::VerificationFailed)
    );
    assert_eq!(
        verify(Offered(Ok(Vec::new()))),
        Err(ErrorCode::VerificationFailed)
    );
    // The signer's key under another kid than the header's does not count.
    let mut renamed = signer.public_jwk();
    renamed.kid = Some("k2".into());
    assert_eq!(
        verify(Offered(Ok(vec![renamed]))),
        Err(ErrorCode::VerificationFailed)
    );
    // The resolver's failure is the result.
    assert_eq!(
        verify(Offered(Err(jwz::Error::new(
            ErrorCode::KeyUnavailable,
            "origin"
        )))),
        Err(ErrorCode::KeyUnavailable)
    );
}

/// A JWK Set is a resolver: it offers the key with the header's kid, and the asynchronous
/// path decides as the synchronous one.
#[test]
fn rfc_7517_5_a_jwk_set_resolves_the_keys_of_a_jws() {
    let registry = Registry::standard();
    let (signer, other) = (generated("k1"), generated("k2"));
    let token = jws::sign(b"hello", HeaderParams::new(), &signer, &strict(), &registry).unwrap();
    let set = jwz::jwk::JwkSet {
        keys: vec![other.public_jwk(), signer.public_jwk()],
    };
    let parsed = || Jws::parse(&token, &strict(), &registry).unwrap();
    assert_eq!(
        parsed()
            .verify_with(&set, &registry, &backend())
            .unwrap()
            .payload(),
        b"hello"
    );
    let verified =
        futures_lite::future::block_on(parsed().verify_with_async(&set, &registry, &backend()))
            .unwrap();
    assert_eq!(verified.payload(), b"hello");
    let without_signer = jwz::jwk::JwkSet {
        keys: vec![other.public_jwk()],
    };
    assert_eq!(
        code(
            futures_lite::future::block_on(parsed().verify_with_async(
                &Offered(Ok(without_signer.keys)),
                &registry,
                &backend()
            ))
            .map(|_| ())
        ),
        Err(ErrorCode::VerificationFailed)
    );
}

// ---- the profile binds signing and keys (RFC 8725 §3.1) ----

/// A key that states the algorithm and curve a test needs, whatever key signs and
/// verifies behind it: an HSM handle that reports what it was told.
struct Stated<'k> {
    key: &'k SoftwareKey<RustCrypto>,
    alg: SignatureAlgorithm,
    curve: Option<Curve>,
}

impl JwsKey for Stated<'_> {
    fn algorithm(&self) -> SignatureAlgorithm {
        self.alg
    }

    fn curve(&self) -> Option<Curve> {
        self.curve
    }
}

impl signature::Signer<Signature> for Stated<'_> {
    fn try_sign(&self, msg: &[u8]) -> Result<Signature, signature::Error> {
        signature::Signer::try_sign(self.key, msg)
    }
}

impl signature::Verifier<Signature> for Stated<'_> {
    fn verify(&self, msg: &[u8], sig: &Signature) -> Result<(), signature::Error> {
        signature::Verifier::verify(self.key, msg, sig)
    }
}

/// A profile that signs ES256 on P-256 and nothing else.
fn es256_only() -> Policy {
    Profile::new("es256", 1).with(&ECDSA_NIST).policy
}

/// RFC 8725 §3.1: the profile decides the algorithms, so jwz signs only what the
/// profile it is given would verify: EdDSA under a profile of ES256 alone, HS256
/// under one without HMAC, RS256 (reserved, not implemented) under any, are refused
/// before the key is asked, by every signing entry point.
#[test]
fn rfc_8725_3_1_signing_refuses_an_algorithm_the_profile_does_not_list() {
    let registry = Registry::standard();
    let ed = SoftwareKey::generate(SignatureAlgorithm::EDDSA, &registry, backend()).unwrap();
    let es = es256_key();
    let policy = es256_only();
    assert_eq!(
        code(jws::sign(
            b"x",
            HeaderParams::new(),
            &ed,
            &policy,
            &registry
        ))
        .err(),
        Some(ErrorCode::PolicyViolation)
    );
    assert_eq!(
        code(futures_lite::future::block_on(jws::sign_async(
            b"x",
            HeaderParams::new(),
            &ed,
            &policy,
            &registry
        )))
        .err(),
        Some(ErrorCode::PolicyViolation)
    );
    assert_eq!(
        code(jws::json::sign(
            b"x",
            &[(&es, HeaderParams::new()), (&ed, HeaderParams::new())],
            &policy,
            &registry
        ))
        .err(),
        Some(ErrorCode::PolicyViolation)
    );
    assert!(jws::sign(b"x", HeaderParams::new(), &es, &policy, &registry).is_ok());

    let rsa = Stated {
        key: &es,
        alg: SignatureAlgorithm::RS256,
        curve: None,
    };
    let interop = Profile::rfc7518_interop(&registry).policy;
    for policy in [strict(), interop] {
        assert_eq!(
            code(jws::sign(
                b"x",
                HeaderParams::new(),
                &rsa,
                &policy,
                &registry
            ))
            .err(),
            Some(ErrorCode::UnsupportedAlgorithm)
        );
    }
    let token = format!("{}.e30.AAAA", jwz::b64::encode(br#"{"alg":"RS256"}"#));
    assert_eq!(
        code(Jws::parse(&token, &strict(), &registry)).err(),
        Some(ErrorCode::UnsupportedAlgorithm)
    );

    #[cfg(feature = "hmac")]
    {
        let hs = SoftwareKey::generate(SignatureAlgorithm::HS256, &registry, backend()).unwrap();
        assert_eq!(
            code(jws::sign(
                b"x",
                HeaderParams::new(),
                &hs,
                &strict(),
                &registry
            ))
            .err(),
            Some(ErrorCode::PolicyViolation)
        );
        let with_hmac = Profile::strict().with(&HMAC).policy;
        let token = jws::sign(b"x", HeaderParams::new(), &hs, &with_hmac, &registry).unwrap();
        Jws::parse(&token, &with_hmac, &registry)
            .unwrap()
            .verify(&hs)
            .unwrap();
    }
}

/// RFC 8725 §3.1 for keys, with RFC 7518 §3.4 (ES256 is P-256): a key on a curve the
/// profile does not list is refused, for signing and for verifying, whatever its
/// algorithm; a resolved one is passed over.
#[test]
fn rfc_8725_3_1_a_key_on_a_curve_the_profile_does_not_list_is_refused() {
    let registry = Registry::standard();
    let es = es256_key();
    let elsewhere = Stated {
        key: &es,
        alg: SignatureAlgorithm::ES256,
        curve: Some(Curve::new("X-OTHER-256")),
    };
    assert_eq!(
        code(jws::sign(
            b"x",
            HeaderParams::new(),
            &elsewhere,
            &strict(),
            &registry
        ))
        .err(),
        Some(ErrorCode::PolicyViolation)
    );
    let token = jws::sign(b"x", HeaderParams::new(), &es, &strict(), &registry).unwrap();
    let parsed = || Jws::parse(&token, &strict(), &registry).unwrap();
    assert_eq!(
        code(parsed().verify(&elsewhere)).err(),
        Some(ErrorCode::PolicyViolation)
    );
    assert_eq!(
        code(futures_lite::future::block_on(
            parsed().verify_async(&elsewhere)
        ))
        .err(),
        Some(ErrorCode::PolicyViolation)
    );
    parsed().verify(&es).unwrap();

    // EdDSA listed, Ed25519 not: the key's curve decides, by every path.
    let ed = SoftwareKey::generate(SignatureAlgorithm::EDDSA, &registry, backend()).unwrap();
    let mut eddsa_on_p256 = es256_only();
    eddsa_on_p256
        .signature_algorithms
        .push(SignatureAlgorithm::EDDSA);
    assert_eq!(
        code(jws::sign(
            b"x",
            HeaderParams::new(),
            &ed,
            &eddsa_on_p256,
            &registry
        ))
        .err(),
        Some(ErrorCode::PolicyViolation)
    );
    let token = jws::sign(b"x", HeaderParams::new(), &ed, &strict(), &registry).unwrap();
    let parsed = || Jws::parse(&token, &eddsa_on_p256, &registry).unwrap();
    assert_eq!(
        code(parsed().verify(&ed)).err(),
        Some(ErrorCode::PolicyViolation)
    );
    let set = jwz::jwk::JwkSet {
        keys: vec![ed.public_jwk()],
    };
    assert_eq!(
        code(parsed().verify_with(&set, &registry, &backend())).err(),
        Some(ErrorCode::VerificationFailed)
    );
    assert_eq!(
        code(futures_lite::future::block_on(parsed().verify_with_async(
            &set,
            &registry,
            &backend()
        )))
        .err(),
        Some(ErrorCode::VerificationFailed)
    );
    // The same token and set under strict, which lists Ed25519, verify.
    Jws::parse(&token, &strict(), &registry)
        .unwrap()
        .verify_with(&set, &registry, &backend())
        .unwrap();
}

/// RFC 8037 §3.1: EdDSA's curve is the key's, and its algorithm registers none; a key
/// that does not state its curve could be on any, and is refused.
#[test]
fn rfc_8037_3_1_an_eddsa_key_that_states_no_curve_is_refused() {
    let registry = Registry::standard();
    let ed = SoftwareKey::generate(SignatureAlgorithm::EDDSA, &registry, backend()).unwrap();
    let silent = Stated {
        key: &ed,
        alg: SignatureAlgorithm::EDDSA,
        curve: None,
    };
    assert_eq!(
        code(jws::sign(
            b"x",
            HeaderParams::new(),
            &silent,
            &strict(),
            &registry
        ))
        .err(),
        Some(ErrorCode::PolicyViolation)
    );
    let token = jws::sign(b"x", HeaderParams::new(), &ed, &strict(), &registry).unwrap();
    assert_eq!(
        code(
            Jws::parse(&token, &strict(), &registry)
                .unwrap()
                .verify(&silent)
        )
        .err(),
        Some(ErrorCode::PolicyViolation)
    );
    // An ES256 key that states none is on ES256's registered curve, P-256.
    let es = es256_key();
    let quiet = Stated {
        key: &es,
        alg: SignatureAlgorithm::ES256,
        curve: None,
    };
    let token = jws::sign(b"x", HeaderParams::new(), &quiet, &strict(), &registry).unwrap();
    Jws::parse(&token, &strict(), &registry)
        .unwrap()
        .verify(&quiet)
        .unwrap();
}

/// The host's own error behind a resolver's failure.
#[derive(Debug)]
struct OriginDown;

impl std::fmt::Display for OriginDown {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("origin down")
    }
}

impl std::error::Error for OriginDown {}

/// A host's cause travels with the error to the caller of `verify_with`, through
/// `source()` only: jwz's own text, code and equality stay what jwz says.
#[test]
fn a_hosts_cause_reaches_the_caller_through_source_only() {
    use std::error::Error as _;
    let registry = Registry::standard();
    let signer = generated("k1");
    let token = jws::sign(b"hello", HeaderParams::new(), &signer, &strict(), &registry).unwrap();
    let failing = Offered(Err(
        jwz::Error::new(ErrorCode::KeyUnavailable, "origin").with_source(OriginDown)
    ));
    let error = Jws::parse(&token, &strict(), &registry)
        .unwrap()
        .verify_with(&failing, &registry, &backend())
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::KeyUnavailable);
    assert!(
        error
            .source()
            .is_some_and(|s| s.downcast_ref::<OriginDown>().is_some())
    );
    assert!(!error.to_string().contains("origin down"), "{error}");
    assert_eq!(error, jwz::Error::new(ErrorCode::KeyUnavailable, "origin"));
    assert!(
        jwz::Error::new(ErrorCode::KeyUnavailable, "origin")
            .source()
            .is_none()
    );
}

/// A host builds a header from JSON to ask a resolver without a token, under the rules a
/// token's header is read by (RFC 7515 §4: a JSON object, RFC 7515 §5.2: no duplicate
/// member).
#[test]
fn rfc_7515_4_a_host_builds_a_header_from_json_as_a_token_has_it() {
    let header = jwz::header::Header::parse(r#"{"alg":"ES256","kid":"k1"}"#).unwrap();
    assert_eq!(header.kid(), Some("k1"));
    let set = jwz::jwk::JwkSet {
        keys: vec![generated("k1").public_jwk(), generated("k2").public_jwk()],
    };
    let keys = jwz::jwk::KeyResolver::resolve(&set, &header, SignatureAlgorithm::ES256).unwrap();
    assert_eq!(keys.len(), 1);
    for text in [r#"{"kid":"a","kid":"b"}"#, "[]", "{"] {
        assert!(jwz::header::Header::parse(text).is_err(), "{text}");
    }
}
