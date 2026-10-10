//! The gematik TI profiles for jwz: [`ti`] for new components and, behind the `legacy`
//! feature, [`ti_legacy`] for the existing interfaces that use brainpoolP256r1. No RSA, no
//! HMAC, no CBC-HMAC.
//!
//! The rules and where they come from:
//!
//! | Rule | Source |
//! | --- | --- |
//! | JWS `ES256` on P-256 | gemSpec_Krypt V2.50.0 Tab_KRYPT_002a (P-256 beside brainpoolP256r1) |
//! | JWS `BP256R1` (legacy) | gemSpec_IDP_Dienst V2.2.0 A_20591-01, A_20695-01, A_20327-02 |
//! | JWE `ECDH-ES` with `A256GCM` | gemSpec_IDP_Dienst V2.2.0 A_20699-03, A_20321-01 |
//! | `epk` on P-256 | gemSpec_Krypt V2.50.0 Tab_KRYPT_002a |
//! | JWE `dir` with `A256GCM` | gemSpec_IDP_Dienst V2.2.0 A_21321 |
//! | `x5c` allowed in headers | gemSpec_Krypt V2.50.0 A_24658-01, gemSpec_IDP_Dienst V2.2.0 §7.7 |
//!
//! ePA's AUT signatures use `ES256` with a brainpoolP256r1 key: that is a key choice, not
//! a profile rule, made with `jwz_brainpool::BrainpoolEs256Key` (feature `legacy`).
//!
//! A_24658-01 limits the age of a client authentication JWT by `iat` (10 minutes) and
//! does not require `exp`; for those tokens set `claims.require_exp = false` and
//! `claims.max_age = Some(600)`.
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use jwz::jwa::{
    ContentEncryptionAlgorithm, Curve, KeyEncryptionAlgorithm, Registry, SignatureAlgorithm,
};
use jwz::profile::{ClaimsPolicy, DEFAULT_MAX_TOKEN_LEN, KeyReferences, Policy, Profile};

/// The TI profile for new components: ES256; ECDH-ES on P-256 and `dir`, both with
/// A256GCM; `x5c` allowed; a JWT must have `exp`, with 60 seconds of clock skew.
pub fn ti() -> Profile {
    Profile {
        name: "ti".into(),
        version: 1,
        policy: Policy {
            signature_algorithms: vec![SignatureAlgorithm::ES256],
            key_encryption_algorithms: vec![
                KeyEncryptionAlgorithm::ECDH_ES,
                KeyEncryptionAlgorithm::DIR,
            ],
            content_encryption_algorithms: vec![ContentEncryptionAlgorithm::A256GCM],
            key_agreement_curves: vec![Curve::P256],
            max_token_len: DEFAULT_MAX_TOKEN_LEN,
            understood_critical: Vec::new(),
            key_references: KeyReferences {
                x5c: true,
                ..KeyReferences::default()
            },
            require_kid: false,
            typ: None,
        },
        claims: ClaimsPolicy {
            issuer: None,
            audience: None,
            leeway: 60,
            require_exp: true,
            max_age: None,
            required: Vec::new(),
        },
    }
}

/// [`ti`] widened by `BP256R1` signatures for existing interfaces (the IDP). Use it with
/// [`registry`], which knows the brainpool names. Brainpool JWE is encryption only (to
/// the IDP's `BP-256` key, gemSpec_IDP_Dienst V2.2.0 §7.8): no profile accepts an `epk`
/// on `BP-256` for decryption yet.
#[cfg(feature = "legacy")]
pub fn ti_legacy() -> Profile {
    let mut profile = ti();
    profile.name = "ti-legacy".into();
    profile
        .policy
        .signature_algorithms
        .push(jwz_brainpool::BP256R1);
    profile
}

/// The registry the TI profiles are meant for: the standard one and, with `legacy`, the
/// brainpool names.
pub fn registry() -> Registry {
    #[cfg(feature = "legacy")]
    let registry = jwz_brainpool::registry();
    #[cfg(not(feature = "legacy"))]
    let registry = Registry::standard();
    registry
}
