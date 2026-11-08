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

//! Stage S5 proof, with the profile binding of jwz 0.2: `ti()` refuses `BP256R1` tokens
//! at parse and for signing, `ti_legacy()` accepts them; no profile decrypts brainpool JWE,
//! and encrypting to a `BP-256` key needs the curve listed; ePA's ES256 on brainpool keys
//! passes `ti()`, which lists `BP-256` for signing keys, and fails `strict()`.
#![cfg(feature = "legacy")]

use std::sync::Arc;

use jwz::ErrorCode;
use jwz::crypto::Backend;
use jwz::crypto::rustcrypto::RustCrypto;
use jwz::header::HeaderParams;
use jwz::jwa::{
    ContentEncryptionAlgorithm as Enc, Curve, KeyEncryptionAlgorithm as Alg, Registry,
    SignatureAlgorithm,
};
use jwz::jwe::{self, EncryptionKey, Jwe};
use jwz::jws::{self, Jws};
use jwz::jwt::{Claims, FixedClock};
use jwz::keys::{SoftwareAgreementKey, SoftwareKey, SymmetricKey};
use jwz::profile::{KeyReferences, Profile};
use ti_jwz::brainpool::{BP_256, BP256R1, BrainpoolEs256Key};
use ti_jwz::{BRAINPOOL_KEY_AGREEMENT, registry, ti, ti_legacy};

fn code<T>(r: Result<T, jwz::Error>) -> Result<T, ErrorCode> {
    r.map_err(|e| e.code())
}

#[test]
fn ti_and_ti_legacy_are_their_constants() {
    let ti = ti();
    assert_eq!((ti.name.as_str(), ti.version), ("ti", 2));
    assert_eq!(ti.policy.signature_algorithms, [SignatureAlgorithm::ES256]);
    assert_eq!(ti.policy.signing_curves, [Curve::P256, BP_256]);
    assert_eq!(
        ti.policy.key_encryption_algorithms,
        [Alg::ECDH_ES, Alg::DIR]
    );
    assert_eq!(ti.policy.content_encryption_algorithms, [Enc::A256GCM]);
    assert_eq!(ti.policy.key_agreement_curves, [Curve::P256]);
    assert_eq!(
        ti.policy.key_references,
        KeyReferences {
            x5c: true,
            ..KeyReferences::default()
        }
    );
    assert_eq!(ti.claims, Profile::new("ti", 2).claims);

    let legacy = ti_legacy();
    assert_eq!(legacy.name, "ti-legacy");
    assert_eq!(
        legacy.policy.signature_algorithms,
        [SignatureAlgorithm::ES256, BP256R1]
    );
    // BP256R1 brings its curve, which ti already lists for ePA: once.
    assert_eq!(legacy.policy.signing_curves, [Curve::P256, BP_256]);
    let mut back = legacy.clone();
    back.name = "ti".into();
    back.policy.signature_algorithms.pop();
    assert_eq!(back, ti);
}

#[test]
fn ti_refuses_a_valid_bp256r1_token_and_ti_legacy_accepts_it() {
    let registry = registry();
    let backend = Arc::new(ti_jwz::brainpool::backend(RustCrypto::new()));
    let idp_sig = SoftwareKey::generate(BP256R1, &registry, backend).unwrap();
    let legacy = ti_legacy();
    // ti() neither signs nor accepts BP256R1.
    assert_eq!(
        code(jws::sign(
            b"{}",
            HeaderParams::new(),
            &idp_sig,
            &ti().policy,
            &registry
        ))
        .err(),
        Some(ErrorCode::PolicyViolation)
    );
    let token = jws::sign(
        br#"{"exp":2000}"#,
        HeaderParams::new().typ("JWT"),
        &idp_sig,
        &legacy.policy,
        &registry,
    )
    .unwrap();

    assert_eq!(
        code(Jws::parse(&token, &ti().policy, &registry)).map(|_| ()),
        Err(ErrorCode::PolicyViolation)
    );
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
    let backend = Arc::new(ti_jwz::brainpool::backend(RustCrypto::new()));
    let idp_enc = SoftwareAgreementKey::generate(BP_256, Arc::clone(&backend)).unwrap();
    let encrypt = |policy: &jwz::profile::Policy| {
        jwe::encrypt(
            b"challenge",
            Enc::A256GCM,
            &jwe::Recipient {
                alg: Alg::ECDH_ES,
                key: EncryptionKey::Public(&idp_enc.public_jwk()),
                header: HeaderParams::new(),
            },
            policy,
            &registry,
            backend.as_ref(),
        )
    };
    // No TI profile lists BP-256 for key agreement, so none encrypts to it by itself...
    for profile in [ti(), ti_legacy()] {
        assert_eq!(
            code(encrypt(&profile.policy)).map(|_| ()),
            Err(ErrorCode::PolicyViolation),
            "{}",
            profile.name
        );
    }
    // ...a TI client adds the curve for its encryption to the IDP's BP-256 key...
    let token = encrypt(&ti_legacy().with(&BRAINPOOL_KEY_AGREEMENT).policy).unwrap();
    // ...and no TI profile accepts a BP-256 epk for decryption yet.
    for profile in [ti(), ti_legacy()] {
        assert_eq!(
            code(Jwe::parse(&token, &profile.policy, &registry)).map(|_| ()),
            Err(ErrorCode::PolicyViolation),
            "{}",
            profile.name
        );
    }
}

/// gemSpec_Krypt V2.51.0 Tab_KRYPT_002a: ePA's AUT signatures are ES256 with a key on
/// brainpoolP256r1, the TI's exception to RFC 7518 §3.4. `ti()` states it by listing
/// `BP-256` among its signing curves; `strict()` keeps RFC 7518's ES256 on P-256 and
/// refuses the same key for signing and verification.
#[test]
fn ti_lists_epas_es256_on_brainpool_keys_and_strict_refuses_them() {
    let registry = registry();
    let backend = RustCrypto::new();
    let aut = BrainpoolEs256Key::generate(backend.rng()).unwrap();
    let header = HeaderParams::new()
        .typ("JWT")
        .x5c(&[b"leaf certificate DER"]);
    let token = jws::sign(
        br#"{"iat":1000}"#,
        header.clone(),
        &aut,
        &ti().policy,
        &registry,
    )
    .unwrap();
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

    let mut strict = Profile::strict().policy;
    strict.key_references.x5c = true;
    assert_eq!(
        code(jws::sign(b"{}", header, &aut, &strict, &registry)).err(),
        Some(ErrorCode::PolicyViolation)
    );
    assert_eq!(
        code(Jws::parse(&token, &strict, &registry).unwrap().verify(&aut)).err(),
        Some(ErrorCode::PolicyViolation)
    );
}

#[test]
fn ti_allows_only_what_gematik_specifies() {
    let registry = registry();
    let backend = Arc::new(RustCrypto::new());
    let interop = Profile::rfc7518_interop(&Registry::standard()).policy;
    let encrypt = |alg: Alg, enc: Enc, key: EncryptionKey<'_>, policy: &jwz::profile::Policy| {
        jwe::encrypt(
            b"x",
            enc,
            &jwe::Recipient {
                alg,
                key,
                header: HeaderParams::new(),
            },
            policy,
            &registry,
            backend.as_ref(),
        )
    };
    let token_key = SymmetricKey::new(vec![7; 32]);
    let p256 = SoftwareAgreementKey::generate(Curve::P256, Arc::clone(&backend)).unwrap();
    let public = p256.public_jwk();
    for (alg, enc, key, allowed, what) in [
        (
            Alg::DIR,
            Enc::A256GCM,
            EncryptionKey::Symmetric(&token_key),
            true,
            "dir A256GCM",
        ),
        (
            Alg::ECDH_ES,
            Enc::A256GCM,
            EncryptionKey::Public(&public),
            true,
            "ECDH-ES A256GCM",
        ),
        (
            Alg::ECDH_ES,
            Enc::A128GCM,
            EncryptionKey::Public(&public),
            false,
            "A128GCM",
        ),
        (
            Alg::ECDH_ES_A256KW,
            Enc::A256GCM,
            EncryptionKey::Public(&public),
            false,
            "ECDH-ES+A256KW",
        ),
        (
            Alg::A256KW,
            Enc::A256GCM,
            EncryptionKey::Symmetric(&token_key),
            false,
            "A256KW",
        ),
    ] {
        // What ti() refuses to read, it refuses to write.
        assert_eq!(
            encrypt(alg, enc, key, &ti().policy).is_ok(),
            allowed,
            "{what}"
        );
        let token = encrypt(alg, enc, key, &interop).unwrap();
        assert_eq!(
            Jwe::parse(&token, &ti().policy, &registry).is_ok(),
            allowed,
            "{what}"
        );
    }
    let eddsa = SoftwareKey::generate(SignatureAlgorithm::EDDSA, &registry, backend).unwrap();
    for profile in [ti(), ti_legacy()] {
        assert_eq!(
            code(jws::sign(
                b"x",
                HeaderParams::new(),
                &eddsa,
                &profile.policy,
                &registry
            ))
            .err(),
            Some(ErrorCode::PolicyViolation),
            "{}",
            profile.name
        );
    }
    let token = jws::sign(b"x", HeaderParams::new(), &eddsa, &interop, &registry).unwrap();
    assert_eq!(
        code(Jws::parse(&token, &ti_legacy().policy, &registry)).map(|_| ()),
        Err(ErrorCode::PolicyViolation)
    );
}
