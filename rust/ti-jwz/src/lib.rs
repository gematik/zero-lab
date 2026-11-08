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

//! The gematik TI profiles for jwz: [`ti`] for new components and, behind the `legacy`
//! feature, [`ti_legacy`] and the [`brainpool`] algorithms for the existing interfaces that
//! use brainpoolP256r1. No RSA, no HMAC, no CBC-HMAC.
//!
//! Like jwz's own, the profiles are the explicit lists their construction results in:
//! jwz's constants for the standard algorithms, and this crate's for brainpool
//! ([`EPA_BRAINPOOL_KEYS`], and with `legacy` `BRAINPOOL_SIGNATURES` and
//! `BRAINPOOL_KEY_AGREEMENT`), composed with [`Profile::with`].
//!
//! The rules and where they come from:
//!
//! | Rule | Source |
//! | --- | --- |
//! | JWS `ES256` on P-256 | gemSpec_Krypt V2.51.0 Tab_KRYPT_002a (P-256 beside brainpoolP256r1) |
//! | JWS `ES256` with keys on brainpoolP256r1 (ePA) | gemSpec_Krypt V2.51.0 Tab_KRYPT_002a; the TI's exception to RFC 7518 §3.4 |
//! | JWS `BP256R1` (legacy) | gemSpec_IDP_Dienst V2.2.0 A_20591-01, A_20695-01, A_20327-02 |
//! | JWE `ECDH-ES` with `A256GCM` | gemSpec_IDP_Dienst V2.2.0 A_20699-03, A_20321-01 |
//! | `epk` on P-256 | gemSpec_Krypt V2.51.0 Tab_KRYPT_002a |
//! | JWE `dir` with `A256GCM` | gemSpec_IDP_Dienst V2.2.0 A_21321 |
//! | `x5c` allowed in headers | gemSpec_Krypt V2.51.0 A_24658-01, gemSpec_IDP_Dienst V2.2.0 §7.7 |
//!
//! ePA's AUT signatures use `ES256` with a brainpoolP256r1 key, which RFC 7518 §3.4 does
//! not allow (ES256 is P-256). [`ti`] states that exception: it lists `BP-256` among its
//! signing curves ([`EPA_BRAINPOOL_KEYS`]), so ES256 with `brainpool::BrainpoolEs256Key`
//! (feature `legacy`) passes [`ti`] and fails jwz's `strict`. The verifier still chooses
//! the key; a token cannot move ES256 onto brainpool by itself.
//!
//! A_24658-01 limits the age of a client authentication JWT by `iat` (10 minutes) and
//! does not require `exp`; for those tokens set `claims.require_exp = false` and
//! `claims.max_age = Some(600)`.
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

#[cfg(feature = "legacy")]
pub mod brainpool;

#[cfg(feature = "legacy")]
use jwz::jwa::KeyEncryptionAlgorithm;
use jwz::jwa::{Curve, Registry};
use jwz::profile::{AES_256_GCM, Algorithms, DIRECT, ECDH_ES_DIRECT_P256, ECDSA_NIST, Profile};

/// The JWK `crv` of brainpoolP256r1 keys (gemSpec_IDP_Dienst V2.2.0 A_20591-01). A name
/// only, without the curve's arithmetic, so that [`ti`] can list it without the
/// `legacy` feature; the arithmetic is in `brainpool` (with `legacy`).
pub const BP_256: Curve = Curve::new("BP-256");

/// Signing keys on brainpoolP256r1 for `ES256`: ePA's AUT signatures (an SMC-B or HBA
/// key), the TI's stated exception to RFC 7518 §3.4, under which ES256 is P-256 only
/// (gemSpec_Krypt V2.51.0 Tab_KRYPT_002a). Adds the curve, not an algorithm.
pub const EPA_BRAINPOOL_KEYS: Algorithms<'static> = Algorithms {
    signing_curves: &[BP_256],
    ..Algorithms::NONE
};

/// `BP256R1` with signing keys on brainpoolP256r1, as the IDP-Dienst signs
/// (gemSpec_IDP_Dienst V2.2.0 A_20591-01, A_20695-01, A_20327-02).
#[cfg(feature = "legacy")]
pub const BRAINPOOL_SIGNATURES: Algorithms<'static> = Algorithms {
    signatures: &[brainpool::BP256R1],
    signing_curves: &[BP_256],
    ..Algorithms::NONE
};

/// `ECDH-ES` to a key on brainpoolP256r1: encrypting to the IDP's `BP-256` encryption
/// key (gemSpec_IDP_Dienst V2.2.0 A_20699-03, §7.8). No shipped profile lists it:
/// with it, a profile would also accept a received `epk` on `BP-256`, and decrypting
/// brainpool JWE is not offered yet. A client adds it for its encryption to the IDP
/// only: `ti_legacy().with(&BRAINPOOL_KEY_AGREEMENT)`.
#[cfg(feature = "legacy")]
pub const BRAINPOOL_KEY_AGREEMENT: Algorithms<'static> = Algorithms {
    key_encryption: &[KeyEncryptionAlgorithm::ECDH_ES],
    key_agreement_curves: &[BP_256],
    ..Algorithms::NONE
};

/// The TI profile for new components: ES256 with keys on P-256 and, for ePA, on
/// brainpoolP256r1; ECDH-ES on P-256 and `dir`, both with A256GCM; `x5c` allowed; a JWT
/// must have `exp`, with 60 seconds of clock skew.
pub fn ti() -> Profile {
    let mut profile = Profile::new("ti", 2)
        .with(&ECDSA_NIST)
        .with(&EPA_BRAINPOOL_KEYS)
        .with(&ECDH_ES_DIRECT_P256)
        .with(&DIRECT)
        .with(&AES_256_GCM);
    profile.policy.key_references.x5c = true;
    profile
}

/// [`ti`] with `BP256R1` signatures ([`BRAINPOOL_SIGNATURES`]) for existing interfaces
/// (the IDP). Use it with [`registry`], which knows the brainpool names. Brainpool JWE is
/// encryption only (to the IDP's `BP-256` key, [`BRAINPOOL_KEY_AGREEMENT`]): no profile
/// accepts an `epk` on `BP-256` for decryption yet.
#[cfg(feature = "legacy")]
pub fn ti_legacy() -> Profile {
    let mut profile = ti().with(&BRAINPOOL_SIGNATURES);
    profile.name = "ti-legacy".into();
    profile
}

/// The registry the TI profiles are meant for: the standard one and, with `legacy`, the
/// brainpool names.
pub fn registry() -> Registry {
    #[cfg(feature = "legacy")]
    let registry = brainpool::registry();
    #[cfg(not(feature = "legacy"))]
    let registry = Registry::standard();
    registry
}
