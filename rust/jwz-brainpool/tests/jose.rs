//! Brainpool through jwz's own JWS and JWE code: `BP256R1` signatures, `ES256` on a
//! brainpool key (ePA), ECDH-ES with an `epk` on `BP-256` (IDP), and the boundaries
//! between brainpool and P-256 keys.

use std::sync::Arc;

use jwz::ErrorCode;
use jwz::crypto::Backend;
use jwz::crypto::rustcrypto::RustCrypto;
use jwz::header::HeaderParams;
use jwz::jwa::{
    ContentEncryptionAlgorithm as Enc, Curve, KeyEncryptionAlgorithm as Alg, SignatureAlgorithm,
};
use jwz::jwe::{self, DecryptionKey, EncryptionKey, Jwe};
use jwz::jws::{self, Jws};
use jwz::keys::{SoftwareAgreementKey, SoftwareKey};
use jwz::profile::{Policy, Profile};
use jwz_brainpool::{BP_256, BP256R1, BrainpoolEs256Key};

fn code<T>(r: Result<T, jwz::Error>) -> Result<T, ErrorCode> {
    r.map_err(|e| e.code())
}

fn interop() -> Policy {
    Profile::rfc7518_interop(&jwz_brainpool::registry()).policy
}

#[test]
fn bp256r1_signs_and_verifies_and_is_bound_to_its_curve() {
    let registry = jwz_brainpool::registry();
    let backend = Arc::new(jwz_brainpool::backend(RustCrypto::new()));
    let key = SoftwareKey::generate(BP256R1, &registry, Arc::clone(&backend)).unwrap();
    assert_eq!(key.public_jwk().crv(), Some("BP-256"));
    let token = jws::sign(b"idp", HeaderParams::new().typ("JWT"), &key).unwrap();
    let jws = Jws::parse(&token, &interop(), &registry).unwrap();
    assert_eq!(jws.algorithm(), BP256R1);
    assert_eq!(jws.verify(&key).unwrap().payload(), b"idp");

    // A BP-256 JWK is not an ES256 key in jwz's registry, and a P-256 key is no BP256R1 key.
    let jwk = key.to_jwk();
    assert_eq!(
        code(SoftwareKey::from_jwk(
            &jwk,
            SignatureAlgorithm::ES256,
            &registry,
            Arc::clone(&backend)
        ))
        .map(|_| ()),
        Err(ErrorCode::KeyMismatch)
    );
    let p256 =
        SoftwareKey::generate(SignatureAlgorithm::ES256, &registry, Arc::clone(&backend)).unwrap();
    assert_eq!(
        code(SoftwareKey::from_jwk(
            &p256.to_jwk(),
            BP256R1,
            &registry,
            backend
        ))
        .map(|_| ()),
        Err(ErrorCode::KeyMismatch)
    );
}

#[test]
fn epa_es256_on_a_brainpool_key() {
    let registry = jwz_brainpool::registry();
    let backend = Arc::new(RustCrypto::new());
    let aut = BrainpoolEs256Key::generate(backend.rng())
        .unwrap()
        .with_kid("aut");
    let token = jws::sign(b"epa", HeaderParams::new(), &aut).unwrap();
    // The header says ES256, as ePA's do.
    let jws = Jws::parse(&token, &Profile::strict().policy, &registry).unwrap();
    assert_eq!(jws.algorithm(), SignatureAlgorithm::ES256);
    assert_eq!(jws.header().kid(), Some("aut"));
    assert_eq!(jws.verify(&aut).unwrap().payload(), b"epa");

    // The public key from its JWK or its point verifies too.
    let public = BrainpoolEs256Key::from_jwk(&aut.public_jwk())
        .unwrap()
        .with_kid("aut");
    let jws = Jws::parse(&token, &Profile::strict().policy, &registry).unwrap();
    assert!(jws.verify(&public).is_ok());

    // A P-256 ES256 key does not verify it, and the brainpool key does not verify a
    // P-256 ES256 token: the curve is the key's, never the header's.
    let p256 =
        SoftwareKey::generate(SignatureAlgorithm::ES256, &registry, Arc::clone(&backend)).unwrap();
    let unkeyed = jws::sign(b"epa", HeaderParams::new(), &aut.clone().with_kid("x")).unwrap();
    let jws = Jws::parse(&unkeyed, &Profile::strict().policy, &registry).unwrap();
    assert!(jws.verify(&p256).is_err());
    let p256_token = jws::sign(b"p256", HeaderParams::new(), &p256).unwrap();
    let jws = Jws::parse(&p256_token, &Profile::strict().policy, &registry).unwrap();
    assert!(
        jws.verify(&BrainpoolEs256Key::from_jwk(&aut.public_jwk()).unwrap())
            .is_err()
    );

    // Not a brainpool key, or a JWK meant for another algorithm: refused.
    assert!(BrainpoolEs256Key::from_jwk(&p256.public_jwk()).is_err());
    let mut other = aut.public_jwk();
    other.alg = Some("BP256R1".into());
    assert!(BrainpoolEs256Key::from_jwk(&other).is_err());
    assert!(BrainpoolEs256Key::from_point(&[4; 65]).is_err());
}

#[test]
fn ecdh_es_with_a_bp256_epk_like_the_idp() {
    let registry = jwz_brainpool::registry();
    let backend = Arc::new(jwz_brainpool::backend(RustCrypto::new()));
    let idp_enc = SoftwareAgreementKey::generate(BP_256, Arc::clone(&backend)).unwrap();
    for alg in [Alg::ECDH_ES, Alg::ECDH_ES_A256KW] {
        let token = jwe::encrypt(
            b"KEY_VERIFIER",
            alg,
            Enc::A256GCM,
            EncryptionKey::Public(&idp_enc.public_jwk()),
            HeaderParams::new().cty("JSON"),
            &registry,
            backend.as_ref(),
        )
        .unwrap();
        let jwe = Jwe::parse(&token, &interop(), &registry).unwrap();
        assert_eq!(jwe.header().epk().unwrap().unwrap().crv(), Some("BP-256"));
        let plaintext = jwe
            .decrypt(DecryptionKey::Agreement(&idp_enc), backend.as_ref())
            .unwrap();
        assert_eq!(plaintext.plaintext(), b"KEY_VERIFIER");
    }

    // A BP-256 epk for a P-256 key, and the other way round: refused before ECDH.
    let p256 = SoftwareAgreementKey::generate(Curve::P256, Arc::clone(&backend)).unwrap();
    let token = jwe::encrypt(
        b"x",
        Alg::ECDH_ES,
        Enc::A256GCM,
        EncryptionKey::Public(&idp_enc.public_jwk()),
        HeaderParams::new(),
        &registry,
        backend.as_ref(),
    )
    .unwrap();
    let jwe = Jwe::parse(&token, &interop(), &registry).unwrap();
    assert_eq!(
        code(jwe.decrypt(DecryptionKey::Agreement(&p256), backend.as_ref())).map(|_| ()),
        Err(ErrorCode::KeyMismatch)
    );

    // Without the brainpool registry, BP-256 is an unknown curve; under strict, a
    // known but disallowed one.
    assert_eq!(
        code(Jwe::parse(
            &token,
            &interop_standard(),
            &jwz::jwa::Registry::standard()
        ))
        .map(|_| ()),
        Err(ErrorCode::UnknownCurve)
    );
    let mut strict = Profile::strict().policy;
    strict.content_encryption_algorithms.push(Enc::A256GCM);
    assert_eq!(
        code(Jwe::parse(&token, &strict, &registry)).map(|_| ()),
        Err(ErrorCode::PolicyViolation)
    );
}

fn interop_standard() -> Policy {
    Profile::rfc7518_interop(&jwz::jwa::Registry::standard()).policy
}
