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

//! RFC 8725 (JSON Web Token Best Current Practices) §3, one test per section, and the
//! requirements draft-ietf-oauth-rfc8725bis-10 adds. Where a section is jwz's to meet,
//! its test proves jwz meets it; where it is the application's, its test proves the part
//! jwz takes (docs/guide.md, "RFC 8725: what jwz does and what is yours"). The tests of the
//! draft carry its name; the traceability table reads RFC numbers only, so the guide's
//! table traces them.
#![cfg(all(
    feature = "crypto-rustcrypto",
    feature = "jws",
    feature = "jwe",
    feature = "jwt"
))]

use std::cell::RefCell;
use std::sync::Arc;

use jwz::ErrorCode;
use jwz::crypto::CryptoError;
use jwz::crypto::rustcrypto::RustCrypto;
use jwz::header::{Header, HeaderParams};
use jwz::jwa::{
    ContentEncryptionAlgorithm, Curve, KeyEncryptionAlgorithm, Registry, SignatureAlgorithm,
};
use jwz::jwe::{self, DecryptionKey, EncryptionKey, Jwe, Recipient};
use jwz::jwk::{Jwk, JwkSet, KeyResolver};
use jwz::jws::{self, Jws};
use jwz::jwt::{Claims, FixedClock};
use jwz::keys::{JwsKey, Signature, SoftwareAgreementKey, SoftwareKey, SymmetricKey};
use jwz::profile::{AES_128_GCM, AES_KW, DIRECT, Policy, Profile};
use serde_json::{Value, json};

fn backend() -> Arc<RustCrypto> {
    Arc::new(RustCrypto::new())
}

fn code<T>(r: Result<T, jwz::Error>) -> Result<T, ErrorCode> {
    r.map_err(|e| e.code())
}

fn strict() -> Policy {
    Profile::strict().policy
}

fn interop() -> Policy {
    Profile::rfc7518_interop(&Registry::standard()).policy
}

fn es256() -> SoftwareKey<RustCrypto> {
    SoftwareKey::generate(SignatureAlgorithm::ES256, &Registry::standard(), backend()).unwrap()
}

fn header(json: &Value) -> Header {
    Header::parse(&json.to_string()).unwrap()
}

/// A compact token with the protected header `json` and placeholder parts: enough for
/// the checks that come before any part but the header is decoded.
fn with_header(json: &Value, parts: usize) -> String {
    let mut token = jwz::b64::encode(json.to_string().as_bytes());
    for _ in 1..parts {
        token.push_str(".AAAA");
    }
    token
}

/// `token` with its protected header changed by `edit`, the other parts as they were.
fn rewrite_header(token: &str, edit: impl FnOnce(&mut Value)) -> String {
    let (protected, rest) = token.split_once('.').unwrap();
    let mut json: Value =
        serde_json::from_slice(&jwz::b64::decode(protected, "header").unwrap()).unwrap();
    edit(&mut json);
    format!("{}.{rest}", jwz::b64::encode(json.to_string().as_bytes()))
}

/// RFC 8725 §3.1: each key is used with exactly one algorithm, checked when it is used.
/// An ES256 key does not verify a token accepted as Ed25519; a JWK published for `EdDSA`
/// is neither made an Ed25519 key nor offered by a JWK Set for one; a shared key published
/// for `A128KW` does not decrypt a `dir` JWE, though its bytes would.
#[test]
fn rfc_8725_3_1_a_key_is_used_only_with_its_one_algorithm() {
    let registry = Registry::standard();
    let ed = SoftwareKey::generate(SignatureAlgorithm::ED25519, &registry, backend()).unwrap();
    let token = jws::sign(b"x", HeaderParams::new(), &ed, &strict(), &registry).unwrap();
    let parsed = || Jws::parse(&token, &strict(), &registry).unwrap();
    assert_eq!(
        code(parsed().verify(&es256())).err(),
        Some(ErrorCode::KeyMismatch)
    );
    assert!(parsed().verify(&ed).is_ok());

    let mut published = ed.public_jwk();
    published.alg = Some("EdDSA".into());
    assert_eq!(
        code(SoftwareKey::from_jwk(
            &published,
            SignatureAlgorithm::ED25519,
            &registry,
            backend()
        ))
        .err(),
        Some(ErrorCode::KeyMismatch)
    );
    let set = JwkSet::parse(&format!(r#"{{"keys":[{}]}}"#, published.to_json())).unwrap();
    assert_eq!(
        code(
            parsed()
                .verify_with(&set, &registry, &backend())
                .map(|_| ())
        ),
        Err(ErrorCode::VerificationFailed)
    );

    let policy = Profile::new("shared", 1)
        .with(&DIRECT)
        .with(&AES_KW)
        .with(&AES_128_GCM)
        .policy;
    let bytes = vec![7; 16];
    let to = Recipient {
        alg: KeyEncryptionAlgorithm::DIR,
        key: EncryptionKey::Symmetric(&SymmetricKey::new(bytes.clone())),
        header: HeaderParams::new(),
    };
    let token = jwe::encrypt(
        b"x",
        ContentEncryptionAlgorithm::A128GCM,
        &to,
        &policy,
        &registry,
        backend().as_ref(),
    )
    .unwrap();
    let wrapping = SymmetricKey::from_jwk(
        &Jwk::parse(&format!(
            r#"{{"kty":"oct","alg":"A128KW","k":"{}"}}"#,
            jwz::b64::encode(&bytes)
        ))
        .unwrap(),
        &registry,
    )
    .unwrap();
    let decrypt = |key: &SymmetricKey| {
        code(
            Jwe::parse(&token, &policy, &registry)
                .unwrap()
                .decrypt(DecryptionKey::Symmetric(key), backend().as_ref())
                .map(|_| ()),
        )
    };
    assert_eq!(decrypt(&wrapping), Err(ErrorCode::KeyMismatch));
    assert_eq!(decrypt(&SymmetricKey::new(bytes)), Ok(()));
}

/// draft-ietf-oauth-rfc8725bis-10 §3.1 and §2.11: the accepted algorithms are an
/// allowlist, and a name matches only exactly: another casing, a trailing space or a
/// name the profile does not list is refused, `none` in any casing among them.
#[test]
fn draft_ietf_oauth_rfc8725bis_10_3_1_algorithms_are_an_allowlist_matched_exactly() {
    let registry = Registry::standard();
    let check = |alg: &str| code(strict().check_jws(&header(&json!({ "alg": alg })), &registry));
    assert_eq!(check("ES256"), Ok(SignatureAlgorithm::ES256));
    for alg in ["es256", "Es256", "ES256 ", "noNE", "none"] {
        assert_eq!(check(alg), Err(ErrorCode::UnsupportedAlgorithm), "{alg}");
    }
    assert_eq!(check("EdDSA"), Err(ErrorCode::PolicyViolation));
}

/// A signer that claims the algorithm `none`; whatever it would sign is never asked for.
struct ClaimsNone(SoftwareKey<RustCrypto>);

impl JwsKey for ClaimsNone {
    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::new("none")
    }
}

impl signature::Signer<Signature> for ClaimsNone {
    fn try_sign(&self, msg: &[u8]) -> Result<Signature, signature::Error> {
        signature::Signer::try_sign(&self.0, msg)
    }
}

/// RFC 8725 §3.2: jwz neither consumes nor produces `none`, and the caller cannot ask it
/// to (draft-ietf-oauth-rfc8725bis-10 §3.2 makes both a MUST NOT): an unsecured token is
/// refused under the most permissive profile, and a signer that claims `none` signs nothing.
#[test]
fn rfc_8725_3_2_none_is_neither_consumed_nor_produced() {
    let registry = Registry::standard();
    for alg in ["none", "None", "NONE"] {
        let token = format!(
            "{}.e30.",
            jwz::b64::encode(format!(r#"{{"alg":"{alg}"}}"#).as_bytes())
        );
        assert_eq!(
            code(Jws::parse(&token, &interop(), &registry)).err(),
            Some(ErrorCode::UnsupportedAlgorithm),
            "{alg}"
        );
    }
    assert_eq!(
        code(jws::sign(
            b"x",
            HeaderParams::new(),
            &ClaimsNone(es256()),
            &interop(),
            &registry
        )),
        Err(ErrorCode::UnsupportedAlgorithm)
    );
}

/// RFC 8725 §3.2: only current algorithms. `strict` lists ES256 and Ed25519 and refuses
/// HMAC and the polymorphic `EdDSA` (draft-ietf-oauth-rfc8725bis-10 §3.2: fully specified
/// names are preferred); RSA PKCS #1 v1.5 key encryption (`RSA1_5`) is not implemented, so
/// no profile accepts it; an ECDSA signature is deterministic (RFC 6979), so the same
/// input signs the same.
#[test]
fn rfc_8725_3_2_strict_allows_only_current_algorithms() {
    let registry = Registry::standard();
    let check = |alg: &str| code(strict().check_jws(&header(&json!({ "alg": alg })), &registry));
    assert_eq!(check("ES256"), Ok(SignatureAlgorithm::ES256));
    assert_eq!(check("Ed25519"), Ok(SignatureAlgorithm::ED25519));
    for alg in [
        "HS256", "HS384", "HS512", "EdDSA", "RS256", "PS256", "ES384",
    ] {
        assert!(check(alg).is_err(), "{alg}");
    }
    let rsa1_5 = with_header(&json!({"alg": "RSA1_5", "enc": "A128GCM"}), 5);
    assert_eq!(
        code(Jwe::parse(&rsa1_5, &interop(), &registry)).err(),
        Some(ErrorCode::UnsupportedAlgorithm)
    );

    let key = es256();
    let sign = || jws::sign(b"x", HeaderParams::new(), &key, &strict(), &registry).unwrap();
    assert_eq!(sign(), sign());
}

/// RFC 8725 §3.3: every cryptographic operation is validated, in a Nested JWT each
/// layer with the keys and algorithms the application supplies, and a failure of either
/// rejects the token: the JWE gives its plaintext only once its tag verifies, the inner
/// JWS its payload only once its signature verifies under its own profile.
#[test]
fn rfc_8725_3_3_every_layer_of_a_nested_jwt_is_validated() {
    let registry = Registry::standard();
    let backend = backend();
    let (issuer, impostor) = (es256(), es256());
    let recipient = SoftwareAgreementKey::generate(Curve::P256, backend.clone()).unwrap();
    let public = recipient.public_jwk();
    let nest = |signer: &SoftwareKey<RustCrypto>| {
        let inner = jws::sign(
            br#"{"iss":"https://idp.example","exp":1900000000}"#,
            HeaderParams::new().typ("JWT"),
            signer,
            &strict(),
            &registry,
        )
        .unwrap();
        let to = Recipient {
            alg: KeyEncryptionAlgorithm::ECDH_ES,
            key: EncryptionKey::Public(&public),
            header: HeaderParams::new().cty("JWT"),
        };
        jwe::encrypt(
            inner.as_bytes(),
            ContentEncryptionAlgorithm::A256GCM,
            &to,
            &strict(),
            &registry,
            backend.as_ref(),
        )
        .unwrap()
    };
    let open = |token: &str| -> Result<Vec<u8>, ErrorCode> {
        let outer = code(Jwe::parse(token, &strict(), &registry))?;
        let decrypted =
            code(outer.decrypt(DecryptionKey::Agreement(&recipient), backend.as_ref()))?;
        let inner = std::str::from_utf8(decrypted.plaintext()).unwrap();
        let verified = code(Jws::parse(inner, &strict(), &registry))?;
        code(verified.verify(&issuer).map(Jws::into_payload))
    };

    let claims = open(&nest(&issuer)).unwrap();
    assert_eq!(
        Claims::parse(&claims).unwrap().iss(),
        Some("https://idp.example")
    );
    assert_eq!(open(&nest(&impostor)), Err(ErrorCode::VerificationFailed));

    let token = nest(&issuer);
    let mut parts: Vec<String> = token.split('.').map(String::from).collect();
    let flipped = if parts[3].starts_with('A') { "B" } else { "A" };
    parts[3].replace_range(..1, flipped);
    assert_eq!(open(&parts.join(".")), Err(ErrorCode::VerificationFailed));
}

/// draft-ietf-oauth-rfc8725bis-10 §3.3: a recipient tells an unsecured JWT, a JWS and a
/// JWE apart: each signed or encrypted form has its own type and parser, neither parses
/// the other, and an unsecured JWT is not parsed at all.
#[test]
fn draft_ietf_oauth_rfc8725bis_10_3_3_unsecured_signed_and_encrypted_are_told_apart() {
    let registry = Registry::standard();
    let backend = backend();
    let signed = jws::sign(b"{}", HeaderParams::new(), &es256(), &strict(), &registry).unwrap();
    let recipient = SoftwareAgreementKey::generate(Curve::P256, backend.clone()).unwrap();
    let public = recipient.public_jwk();
    let to = Recipient {
        alg: KeyEncryptionAlgorithm::ECDH_ES,
        key: EncryptionKey::Public(&public),
        header: HeaderParams::new(),
    };
    let encrypted = jwe::encrypt(
        b"{}",
        ContentEncryptionAlgorithm::A256GCM,
        &to,
        &strict(),
        &registry,
        backend.as_ref(),
    )
    .unwrap();
    assert!(Jws::parse(&signed, &strict(), &registry).is_ok());
    assert!(Jwe::parse(&encrypted, &strict(), &registry).is_ok());
    assert_eq!(
        code(Jws::parse(&encrypted, &strict(), &registry)).err(),
        Some(ErrorCode::Malformed)
    );
    assert_eq!(
        code(Jwe::parse(&signed, &strict(), &registry)).err(),
        Some(ErrorCode::Malformed)
    );
    let unsecured = format!("{}.e30.", jwz::b64::encode(br#"{"alg":"none"}"#));
    assert_eq!(
        code(Jws::parse(&unsecured, &interop(), &registry)).err(),
        Some(ErrorCode::UnsupportedAlgorithm)
    );
}

/// RFC 8725 §3.4: the `epk` of an ECDH-ES JWE is validated on the recipient's curve
/// before the key agreement: a point off the curve refuses the JWE, and the recipient's
/// private key never multiplies it.
#[test]
fn rfc_8725_3_4_an_epk_off_the_curve_is_refused() {
    let registry = Registry::standard();
    let backend = backend();
    let recipient = SoftwareAgreementKey::generate(Curve::P256, backend.clone()).unwrap();
    let public = recipient.public_jwk();
    let to = Recipient {
        alg: KeyEncryptionAlgorithm::ECDH_ES,
        key: EncryptionKey::Public(&public),
        header: HeaderParams::new(),
    };
    let token = jwe::encrypt(
        b"x",
        ContentEncryptionAlgorithm::A256GCM,
        &to,
        &strict(),
        &registry,
        backend.as_ref(),
    )
    .unwrap();
    // x of RFC 7518 Appendix C's ephemeral key, y of its recipient's: not a point of P-256.
    let off_curve = rewrite_header(&token, |h| {
        h["epk"]["x"] = json!("gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0");
        h["epk"]["y"] = json!("e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck");
    });
    assert_eq!(
        code(
            Jwe::parse(&off_curve, &strict(), &registry)
                .and_then(|jwe| jwe.decrypt(DecryptionKey::Agreement(&recipient), backend.as_ref()))
                .map(|_| ())
        ),
        Err(ErrorCode::Crypto(CryptoError::InvalidKey))
    );
}

/// RFC 8725 §3.5: a human-memorable password is no HMAC key: a key shorter than the hash
/// output is refused, as RFC 7518 §3.2 demands. Where a key comes from is the
/// application's; jwz generates its own keys from the backend's random source only.
#[cfg(feature = "hmac")]
#[test]
fn rfc_8725_3_5_a_password_is_no_hmac_key() {
    let password = Jwk::parse(&format!(
        r#"{{"kty":"oct","k":"{}"}}"#,
        jwz::b64::encode(b"correct horse battery")
    ))
    .unwrap();
    assert_eq!(
        code(SoftwareKey::from_jwk(
            &password,
            SignatureAlgorithm::HS256,
            &Registry::standard(),
            backend()
        ))
        .err(),
        Some(ErrorCode::KeyLength)
    );
}

/// RFC 8725 §3.6: jwz does not compress before encryption: `zip` cannot be set on a JWE
/// it produces, and a JWE that carries it is refused before any key is used.
#[test]
fn rfc_8725_3_6_compression_is_neither_produced_nor_accepted() {
    assert_eq!(
        code(HeaderParams::new().param("zip", json!("DEF"))).err(),
        Some(ErrorCode::InvalidMember)
    );
    let zipped = with_header(&json!({"alg": "dir", "enc": "A128GCM", "zip": "DEF"}), 5);
    assert_eq!(
        code(Jwe::parse(&zipped, &interop(), &Registry::standard())).err(),
        Some(ErrorCode::PolicyViolation)
    );
}

/// draft-ietf-oauth-rfc8725bis-10 §3.15 and §2.12: jwz decompresses nothing, so there is
/// no decompression to bound: a JWE it encrypted, rewritten to say `zip`, is refused when
/// parsed, before decryption.
#[test]
fn draft_ietf_oauth_rfc8725bis_10_3_15_nothing_is_decompressed() {
    let registry = Registry::standard();
    let policy = interop();
    let key = SymmetricKey::new(vec![7; 16]);
    let to = Recipient {
        alg: KeyEncryptionAlgorithm::DIR,
        key: EncryptionKey::Symmetric(&key),
        header: HeaderParams::new(),
    };
    let token = jwe::encrypt(
        b"x",
        ContentEncryptionAlgorithm::A128GCM,
        &to,
        &policy,
        &registry,
        backend().as_ref(),
    )
    .unwrap();
    assert!(Jwe::parse(&token, &policy, &registry).is_ok());
    let zipped = rewrite_header(&token, |h| h["zip"] = json!("DEF"));
    assert_eq!(
        code(Jwe::parse(&zipped, &policy, &registry)).err(),
        Some(ErrorCode::PolicyViolation)
    );
}

/// RFC 8725 §3.7: headers and claims are UTF-8 JSON and nothing else: bytes that are not
/// UTF-8, UTF-16, a byte order mark and an escaped lone surrogate are refused; UTF-8
/// beyond ASCII is read as it is.
#[test]
fn rfc_8725_3_7_headers_and_claims_are_utf_8_only() {
    let utf16: Vec<u8> = r#"{"alg":"ES256"}"#.encode_utf16().flat_map(u16::to_le_bytes).collect();
    for (text, what) in [
        (b"{\"sub\":\"\xff\"}".to_vec(), "not UTF-8"),
        (b"{\"sub\":\"\xc3\"}".to_vec(), "a truncated sequence"),
        (utf16, "UTF-16"),
        (b"\xef\xbb\xbf{\"sub\":\"x\"}".to_vec(), "a byte order mark"),
        (br#"{"sub":"\ud800"}"#.to_vec(), "a lone surrogate"),
    ] {
        assert_eq!(
            code(Claims::parse(&text)).err(),
            Some(ErrorCode::Json),
            "claims: {what}"
        );
        assert_eq!(
            code(Header::decode(&jwz::b64::encode(&text))).err(),
            Some(ErrorCode::Json),
            "header: {what}"
        );
    }
    let claims = Claims::parse("{\"sub\":\"J\u{fc}rgen\"}".as_bytes()).unwrap();
    assert_eq!(claims.sub(), Some("Jürgen"));
}

/// RFC 8725 §3.8: which keys belong to which issuer is the application's knowledge; jwz
/// verifies with the keys the application resolves for the issuer it expects, then holds
/// `iss` to that issuer. A token that names another issuer but verifies with the expected
/// issuer's keys is refused, and `sub` is offered to the application only as a string.
#[test]
fn rfc_8725_3_8_the_issuer_is_held_to_the_one_whose_keys_verified() {
    let registry = Registry::standard();
    let idp = es256().with_kid("idp-1");
    let keys = JwkSet::parse(&format!(r#"{{"keys":[{}]}}"#, idp.public_jwk().to_json())).unwrap();
    let mut rules = Profile::strict().claims;
    rules.issuer = Some("https://idp.example".into());
    let check = |claims: &str| {
        let token = jws::sign(
            claims.as_bytes(),
            HeaderParams::new(),
            &idp,
            &strict(),
            &registry,
        )
        .unwrap();
        let verified = Jws::parse(&token, &strict(), &registry)
            .unwrap()
            .verify_with(&keys, &registry, &backend())
            .unwrap();
        code(Claims::parse(verified.payload()).and_then(|c| c.validate(&rules, &FixedClock(0))))
    };
    assert_eq!(
        check(r#"{"iss":"https://idp.example","sub":"alice","exp":60}"#),
        Ok(())
    );
    assert_eq!(
        check(r#"{"iss":"https://other.example","exp":60}"#),
        Err(ErrorCode::InvalidClaim)
    );
    assert_eq!(check(r#"{"exp":60}"#), Err(ErrorCode::InvalidClaim));
    assert_eq!(
        check(r#"{"iss":"https://idp.example","sub":1,"exp":60}"#),
        Err(ErrorCode::InvalidClaim)
    );
}

/// RFC 8725 §3.9: a recipient that names itself as the audience refuses a token without
/// `aud` and one whose `aud` does not contain it.
#[test]
fn rfc_8725_3_9_a_token_without_or_for_another_audience_is_refused() {
    let mut rules = Profile::strict().claims;
    rules.audience = Some("https://rp.example".into());
    let check = |claims: &str| {
        code(Claims::parse(claims.as_bytes()).and_then(|c| c.validate(&rules, &FixedClock(0))))
    };
    assert_eq!(check(r#"{"aud":"https://rp.example","exp":60}"#), Ok(()));
    assert_eq!(
        check(r#"{"aud":["https://other.example","https://rp.example"],"exp":60}"#),
        Ok(())
    );
    for claims in [
        r#"{"exp":60}"#,
        r#"{"aud":"https://other.example","exp":60}"#,
        r#"{"aud":[],"exp":60}"#,
        r#"{"aud":"HTTPS://RP.EXAMPLE","exp":60}"#,
    ] {
        assert_eq!(check(claims), Err(ErrorCode::InvalidClaim), "{claims}");
    }
}

/// A resolver that records the `kid` it was asked for and offers `keys`.
struct Recording {
    asked: RefCell<Option<String>>,
    keys: JwkSet,
}

impl KeyResolver for Recording {
    fn resolve(&self, header: &Header, alg: SignatureAlgorithm) -> Result<Vec<Jwk>, jwz::Error> {
        *self.asked.borrow_mut() = header.kid().map(String::from);
        self.keys.resolve(header, alg)
    }
}

/// RFC 8725 §3.10: received values are input, not instructions. `jku`, `x5u`, `jwk` and
/// `x5c` in a token are refused unless the profile opts into them, and jwz fetches no
/// URL in any case; a `kid` reaches the application's resolver as received and a JWK Set
/// only compares it, so a `kid` built for injection finds no key.
#[test]
fn rfc_8725_3_10_key_references_are_refused_and_kid_is_only_compared() {
    let registry = Registry::standard();
    for (name, value) in [
        ("jku", json!("https://attacker.example/jwks")),
        ("x5u", json!("https://attacker.example/chain.pem")),
        (
            "jwk",
            json!({"kty": "EC", "crv": "P-256", "x": "AA", "y": "AA"}),
        ),
        ("x5c", json!(["AA=="])),
    ] {
        let mut members = json!({"alg": "ES256"});
        members[name] = value;
        assert_eq!(
            code(strict().check_jws(&header(&members), &registry)).err(),
            Some(ErrorCode::PolicyViolation),
            "{name}"
        );
    }

    let injected = "k1' OR '1'='1";
    let signer = es256().with_kid(injected);
    let token = jws::sign(b"x", HeaderParams::new(), &signer, &strict(), &registry).unwrap();
    let mut listed = signer.public_jwk();
    listed.kid = Some("k1".into());
    let resolver = Recording {
        asked: RefCell::new(None),
        keys: JwkSet::parse(&format!(r#"{{"keys":[{}]}}"#, listed.to_json())).unwrap(),
    };
    assert_eq!(
        code(
            Jws::parse(&token, &strict(), &registry)
                .unwrap()
                .verify_with(&resolver, &registry, &backend())
                .map(|_| ())
        ),
        Err(ErrorCode::VerificationFailed)
    );
    assert_eq!(resolver.asked.borrow().as_deref(), Some(injected));
}

/// RFC 8725 §3.11: explicit typing. A profile with a `typ` refuses a token without it or
/// with another, the generic `JWT` included; `application/` may be left off and case does
/// not matter, as RFC 7515 §4.1.9 compares media types. A producer sets the type with
/// `HeaderParams::typ`, and the token verifies under the profile that requires it.
#[test]
fn rfc_8725_3_11_a_profile_requires_the_explicit_type() {
    let registry = Registry::standard();
    let mut policy = strict();
    policy.typ = Some("secevent+jwt".into());
    let check = |members: Value| code(policy.check_jws(&header(&members), &registry));
    for typ in ["secevent+jwt", "application/secevent+jwt", "SecEvent+JWT"] {
        assert_eq!(
            check(json!({"alg": "ES256", "typ": typ})),
            Ok(SignatureAlgorithm::ES256),
            "{typ}"
        );
    }
    assert_eq!(
        check(json!({"alg": "ES256"})),
        Err(ErrorCode::PolicyViolation)
    );
    for typ in ["JWT", "application/jwt", "at+jwt", "secevent"] {
        assert_eq!(
            check(json!({"alg": "ES256", "typ": typ})),
            Err(ErrorCode::PolicyViolation),
            "{typ}"
        );
    }
    let key = es256();
    let token = jws::sign(
        b"{}",
        HeaderParams::new().typ("secevent+jwt"),
        &key,
        &policy,
        &registry,
    )
    .unwrap();
    assert!(
        Jws::parse(&token, &policy, &registry)
            .unwrap()
            .verify(&key)
            .is_ok()
    );
}

/// RFC 8725 §3.12: the rules for two kinds of token from one issuer are mutually exclusive
/// when their profiles differ in `typ` and audience: each kind's profile refuses the
/// other's tokens, the header before any signature is checked, the claims after.
#[test]
fn rfc_8725_3_12_each_kind_of_token_is_refused_by_the_others_profile() {
    let registry = Registry::standard();
    let key = es256();
    let kind = |typ: &str, audience: &str| {
        let mut profile = Profile::strict();
        profile.policy.typ = Some(typ.into());
        profile.claims.audience = Some(audience.into());
        profile
    };
    let (access, logout) = (
        kind("at+jwt", "https://api.example"),
        kind("logout+jwt", "client"),
    );
    let token = |profile: &Profile| {
        let claims = json!({"aud": profile.claims.audience, "exp": 60}).to_string();
        let typ = profile.policy.typ.as_deref().unwrap();
        jws::sign(
            claims.as_bytes(),
            HeaderParams::new().typ(typ),
            &key,
            &profile.policy,
            &registry,
        )
        .unwrap()
    };
    // With `typ_checked` false the header passes, so the claims rules are what refuses.
    let accept = |token: &str, profile: &Profile, typ_checked: bool| {
        let policy = if typ_checked {
            &profile.policy
        } else {
            &strict()
        };
        let verified = code(Jws::parse(token, policy, &registry))?;
        let payload = code(verified.verify(&key).map(Jws::into_payload))?;
        code(Claims::parse(&payload).and_then(|c| c.validate(&profile.claims, &FixedClock(0))))
    };
    for (own, other) in [(&access, &logout), (&logout, &access)] {
        let token = token(own);
        assert_eq!(accept(&token, own, true), Ok(()));
        assert_eq!(accept(&token, other, true), Err(ErrorCode::PolicyViolation));
        assert_eq!(accept(&token, other, false), Err(ErrorCode::InvalidClaim));
    }
}

/// draft-ietf-oauth-rfc8725bis-10 §3.13 and §2.10: jwz implements no PBES2, so there is no
/// iteration count to bound: a PBES2 JWE is refused, whatever its `p2c`, under every
/// profile and before anything is derived.
#[test]
fn draft_ietf_oauth_rfc8725bis_10_3_13_pbes2_is_refused_whatever_its_count() {
    for alg in [
        "PBES2-HS256+A128KW",
        "PBES2-HS384+A192KW",
        "PBES2-HS512+A256KW",
    ] {
        let token = with_header(
            &json!({"alg": alg, "enc": "A128GCM", "p2s": "AAAAAAAAAAAAAAAAAAAAAA", "p2c": u64::from(u32::MAX)}),
            5,
        );
        assert_eq!(
            code(Jwe::parse(&token, &interop(), &Registry::standard())).err(),
            Some(ErrorCode::UnsupportedAlgorithm),
            "{alg}"
        );
    }
}

/// draft-ietf-oauth-rfc8725bis-10 §3.14 and §2.13: a compact token is base64url and dots
/// only; a brace, a quote, whitespace, padding or a character outside ASCII in any part
/// refuses it, and a JSON serialization is not read as a compact token. The claims come
/// only from the payload a verified JWS returns, never from the token's text.
#[test]
fn draft_ietf_oauth_rfc8725bis_10_3_14_a_compact_token_is_base64url_and_dots_only() {
    let registry = Registry::standard();
    let backend = backend();
    let key = es256();
    let signed = jws::sign(b"{}", HeaderParams::new(), &key, &strict(), &registry).unwrap();
    let recipient = SoftwareAgreementKey::generate(Curve::P256, backend.clone()).unwrap();
    let public = recipient.public_jwk();
    let to = Recipient {
        alg: KeyEncryptionAlgorithm::ECDH_ES_A128KW,
        key: EncryptionKey::Public(&public),
        header: HeaderParams::new(),
    };
    let encrypted = jwe::encrypt(
        b"{}",
        ContentEncryptionAlgorithm::A256GCM,
        &to,
        &strict(),
        &registry,
        backend.as_ref(),
    )
    .unwrap();
    let with_char_in = |token: &str, part: usize, c: char| {
        let mut parts: Vec<String> = token.split('.').map(String::from).collect();
        parts[part].insert(0, c);
        parts.join(".")
    };
    for c in ['{', '}', '"', ' ', '\n', '=', '+', '/', '\u{fc}'] {
        for part in 0..3 {
            let token = with_char_in(&signed, part, c);
            assert_eq!(
                code(Jws::parse(&token, &strict(), &registry)).err(),
                Some(ErrorCode::Base64),
                "jws part {part}, {c:?}"
            );
        }
        for part in 0..5 {
            let token = with_char_in(&encrypted, part, c);
            assert_eq!(
                code(Jwe::parse(&token, &strict(), &registry)).err(),
                Some(ErrorCode::Base64),
                "jwe part {part}, {c:?}"
            );
        }
    }
    let json =
        jws::json::sign(b"{}", &[(&key, HeaderParams::new())], &strict(), &registry).unwrap();
    assert!(Jws::parse(&json, &strict(), &registry).is_err());
}
