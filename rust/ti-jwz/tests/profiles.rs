//! Stage S5 proof: `ti()` refuses `BP256R1` tokens at parse, `ti_legacy()` accepts them;
//! no profile decrypts brainpool JWE;
//! ePA's ES256 on brainpool keys needs no legacy profile, only the legacy key.
#![cfg(feature = "legacy")]

use std::sync::Arc;

use jwz::ErrorCode;
use jwz::crypto::Backend;
use jwz::crypto::rustcrypto::RustCrypto;
use jwz::header::HeaderParams;
use jwz::jwa::{
    ContentEncryptionAlgorithm as Enc, Curve, KeyEncryptionAlgorithm as Alg, SignatureAlgorithm,
};
use jwz::jwe::{self, EncryptionKey, Jwe};
use jwz::jws::{self, Jws};
use jwz::jwt::{Claims, FixedClock};
use jwz::keys::{SoftwareAgreementKey, SoftwareKey, SymmetricKey};
use jwz_brainpool::{BP_256, BP256R1, BrainpoolEs256Key};
use ti_jwz::{registry, ti, ti_legacy};

fn code<T>(r: Result<T, jwz::Error>) -> Result<T, ErrorCode> {
    r.map_err(|e| e.code())
}

#[test]
fn ti_refuses_a_valid_bp256r1_token_and_ti_legacy_accepts_it() {
    let registry = registry();
    let backend = Arc::new(jwz_brainpool::backend(RustCrypto::new()));
    let idp_sig = SoftwareKey::generate(BP256R1, &registry, backend).unwrap();
    let token = jws::sign(br#"{"exp":2000}"#, HeaderParams::new().typ("JWT"), &idp_sig).unwrap();

    assert_eq!(
        code(Jws::parse(&token, &ti().policy, &registry)).map(|_| ()),
        Err(ErrorCode::PolicyViolation)
    );
    let legacy = ti_legacy();
    let verified = Jws::parse(&token, &legacy.policy, &registry)
        .unwrap()
        .verify(&idp_sig)
        .unwrap();
    let claims = Claims::parse(verified.payload()).unwrap();
    assert!(claims.validate(&legacy.claims, &FixedClock(1000)).is_ok());
    assert_eq!(
        code(claims.validate(&legacy.claims, &FixedClock(2060))),
        Err(ErrorCode::Expired)
    );
}

#[test]
fn brainpool_jwe_is_encryption_only() {
    let registry = registry();
    let backend = Arc::new(jwz_brainpool::backend(RustCrypto::new()));
    let idp_enc = SoftwareAgreementKey::generate(BP_256, Arc::clone(&backend)).unwrap();
    // A TI client encrypts to the IDP's BP-256 key...
    let token = jwe::encrypt(
        b"challenge",
        Alg::ECDH_ES,
        Enc::A256GCM,
        EncryptionKey::Public(&idp_enc.public_jwk()),
        HeaderParams::new(),
        &registry,
        backend.as_ref(),
    )
    .unwrap();
    // ...but no TI profile accepts a BP-256 epk for decryption yet.
    for profile in [ti(), ti_legacy()] {
        assert_eq!(
            code(Jwe::parse(&token, &profile.policy, &registry)).map(|_| ()),
            Err(ErrorCode::PolicyViolation),
            "{}",
            profile.name
        );
    }
}

#[test]
fn epa_es256_with_a_brainpool_key_passes_ti() {
    let registry = registry();
    let backend = RustCrypto::new();
    let aut = BrainpoolEs256Key::generate(backend.rng()).unwrap();
    let header = HeaderParams::new()
        .typ("JWT")
        .x5c(&[b"leaf certificate DER"]);
    let token = jws::sign(br#"{"iat":1000}"#, header, &aut).unwrap();
    let jws = Jws::parse(&token, &ti().policy, &registry).unwrap();
    assert_eq!(
        jws.header().x5c().unwrap().unwrap()[0],
        b"leaf certificate DER"
    );
    let verified = jws.verify(&aut).unwrap();

    // A_24658-01: iat at most 10 minutes old, no exp required.
    let mut claims_policy = ti().claims;
    claims_policy.require_exp = false;
    claims_policy.max_age = Some(600);
    let claims = Claims::parse(verified.payload()).unwrap();
    assert!(claims.validate(&claims_policy, &FixedClock(1600)).is_ok());
    assert_eq!(
        code(claims.validate(&claims_policy, &FixedClock(1661))),
        Err(ErrorCode::Expired)
    );
}

#[test]
fn ti_allows_only_what_gematik_specifies() {
    let registry = registry();
    let backend = Arc::new(RustCrypto::new());
    let encrypt = |alg: Alg, enc: Enc, key: EncryptionKey<'_>| {
        jwe::encrypt(
            b"x",
            alg,
            enc,
            key,
            HeaderParams::new(),
            &registry,
            backend.as_ref(),
        )
        .unwrap()
    };
    let token_key = SymmetricKey::new(vec![7; 32]);
    let p256 = SoftwareAgreementKey::generate(Curve::P256, Arc::clone(&backend)).unwrap();
    let public = p256.public_jwk();
    for (token, allowed, what) in [
        (
            encrypt(Alg::DIR, Enc::A256GCM, EncryptionKey::Symmetric(&token_key)),
            true,
            "dir A256GCM",
        ),
        (
            encrypt(Alg::ECDH_ES, Enc::A256GCM, EncryptionKey::Public(&public)),
            true,
            "ECDH-ES A256GCM",
        ),
        (
            encrypt(Alg::ECDH_ES, Enc::A128GCM, EncryptionKey::Public(&public)),
            false,
            "A128GCM",
        ),
        (
            encrypt(
                Alg::ECDH_ES_A256KW,
                Enc::A256GCM,
                EncryptionKey::Public(&public),
            ),
            false,
            "ECDH-ES+A256KW",
        ),
        (
            encrypt(
                Alg::A256KW,
                Enc::A256GCM,
                EncryptionKey::Symmetric(&token_key),
            ),
            false,
            "A256KW",
        ),
    ] {
        assert_eq!(
            Jwe::parse(&token, &ti().policy, &registry).is_ok(),
            allowed,
            "{what}"
        );
    }
    let eddsa = SoftwareKey::generate(SignatureAlgorithm::EDDSA, &registry, backend).unwrap();
    let token = jws::sign(b"x", HeaderParams::new(), &eddsa).unwrap();
    assert_eq!(
        code(Jws::parse(&token, &ti_legacy().policy, &registry)).map(|_| ()),
        Err(ErrorCode::PolicyViolation)
    );
}
