//! brainpoolP256r1 for jwz: the JWS algorithm `BP256R1` and the JWK curve `BP-256`, as
//! gematik uses them on existing TI interfaces (IDP discovery documents and tokens,
//! VAU handshakes, SMC-B and HBA keys). Legacy support only: new components use P-256
//! and must not depend on this crate (`just brainpool-absent <crate>` checks that).
//!
//! Neither identifier is registered with IANA; they are gematik's (gemSpec_IDP_Dienst
//! V2.2.0, A_20591-01, A_20695-01, A_20327-02), mirrored by `go/brainpool/josebp` in this
//! repository. Brainpool ECDH-ES uses the standard `ECDH-ES` names with an `epk` on
//! `BP-256` (A_21321).
//!
//! The crate is names plus primitives: [`register`] adds the names to a registry, and
//! [`Bp256`] implements jwz's [`Ecdsa`] and [`Ecdh`] traits, which [`backend`] adds to any
//! base backend through [`Extended`]. Parsing, headers, policies, the Concat KDF and the
//! key types all stay in jwz and are the same code as for P-256.
//!
//! ePA signs with the standard `ES256` but a brainpoolP256r1 key (an SMC-B or HBA AUT
//! key, the certificate in `x5c`), which RFC 7518 §3.4 does not allow: ES256 is P-256.
//! jwz keeps that meaning; [`BrainpoolEs256Key`] is the explicit exception, a key whose
//! algorithm is `ES256` and whose curve is brainpoolP256r1. The verifier chooses it, so a
//! token can never move ES256 onto brainpool by itself.
//!
//! ```
//! use std::sync::Arc;
//! use jwz::crypto::rustcrypto::RustCrypto;
//! use jwz::header::HeaderParams;
//! use jwz::jws::{self, Jws};
//! use jwz::keys::SoftwareKey;
//! use jwz::profile::Profile;
//!
//! let registry = jwz_brainpool::registry();
//! let backend = Arc::new(jwz_brainpool::backend(RustCrypto::new()));
//! let key = SoftwareKey::generate(jwz_brainpool::BP256R1, &registry, backend)?;
//! let token = jws::sign(b"legacy", HeaderParams::new(), &key)?;
//!
//! let mut policy = Profile::strict().policy;
//! policy.signature_algorithms.push(jwz_brainpool::BP256R1);
//! let verified = Jws::parse(&token, &policy, &registry)?.verify(&key)?;
//! assert_eq!(verified.payload(), b"legacy");
//! # Ok::<(), jwz::Error>(())
//! ```
#![no_std]
#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]

extern crate alloc;

mod es256;

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;

pub use es256::BrainpoolEs256Key;

use bp256::BrainpoolP256r1;
use ecdsa::signature::{Signer as _, Verifier as _};
use jwz::crypto::{Backend, CryptoError, Ecdh, Ecdsa, Extended, KeyPair, Rng, Zeroizing};
use jwz::jwa::{
    Curve, CurveEntry, HashAlgorithm, KeyType, Registry, RegistryError, SignatureAlgorithm,
    SignatureEntry, Support,
};

/// ECDSA over brainpoolP256r1 with SHA-256, signature `r || s` (gemSpec_IDP_Dienst
/// A_20591-01).
pub const BP256R1: SignatureAlgorithm = SignatureAlgorithm::new("BP256R1");

/// The JWK `crv` of brainpoolP256r1 keys.
pub const BP_256: Curve = Curve::new("BP-256");

/// Adds `BP-256` and `BP256R1` to `registry`.
///
/// # Errors
///
/// [`RegistryError::Duplicate`] if either name is already registered.
pub fn register(registry: &mut Registry) -> Result<(), RegistryError> {
    registry.register_curve(CurveEntry {
        crv: BP_256,
        key_type: KeyType::EC,
        coordinate_len: 32,
        support: Support::Available,
    })?;
    registry.register_signature(SignatureEntry {
        alg: BP256R1,
        key_type: KeyType::EC,
        curve: Some(BP_256),
        hash: Some(HashAlgorithm::Sha256),
        support: Support::Available,
    })
}

/// The standard registry with `BP-256` and `BP256R1` added.
pub fn registry() -> Registry {
    let mut registry = Registry::standard();
    // The standard registry has neither name, so registering cannot collide.
    let _ = register(&mut registry);
    registry
}

/// `base` with ECDSA and ECDH on `BP-256`.
pub fn backend<B: Backend>(base: B) -> Extended<B> {
    Extended::new(base)
        .with_ecdsa(Box::new(Bp256))
        .with_ecdh(Box::new(Bp256))
}

/// brainpoolP256r1 (RFC 5639 §3.4): ECDSA with SHA-256 and ECDH, on RustCrypto's `bp256`.
#[derive(Clone, Copy, Debug, Default)]
pub struct Bp256;

type SecretKey = elliptic_curve::SecretKey<BrainpoolP256r1>;
type PublicKey = elliptic_curve::PublicKey<BrainpoolP256r1>;

impl Ecdsa for Bp256 {
    fn curve(&self) -> Curve {
        BP_256
    }

    fn hash(&self) -> HashAlgorithm {
        HashAlgorithm::Sha256
    }

    fn public_key(&self, secret: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let key = SecretKey::from_slice(secret).map_err(|_| CryptoError::InvalidKey)?;
        Ok(key.public_key().to_sec1_bytes().to_vec())
    }

    fn sign(&self, secret: &[u8], msg: &[u8], _rng: &dyn Rng) -> Result<Vec<u8>, CryptoError> {
        // RFC 6979 deterministic nonces, as for ES256: `rng` is unused.
        let key = ecdsa::SigningKey::<BrainpoolP256r1>::from_slice(secret)
            .map_err(|_| CryptoError::InvalidKey)?;
        let signature: ecdsa::Signature<BrainpoolP256r1> = key.sign(msg);
        Ok(signature.to_bytes().to_vec())
    }

    fn verify(&self, public: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), CryptoError> {
        let key = ecdsa::VerifyingKey::<BrainpoolP256r1>::from_sec1_bytes(public)
            .map_err(|_| CryptoError::InvalidKey)?;
        // `r || s`, 32 bytes each, as RFC 7518 §3.4 defines it for ES256.
        let signature = ecdsa::Signature::<BrainpoolP256r1>::from_slice(sig)
            .map_err(|_| CryptoError::VerificationFailed)?;
        key.verify(msg, &signature)
            .map_err(|_| CryptoError::VerificationFailed)
    }
}

impl Ecdh for Bp256 {
    fn curve(&self) -> Curve {
        BP_256
    }

    fn generate(&self, rng: &dyn Rng) -> Result<KeyPair, CryptoError> {
        // Rejection sampling: the order is just below 2^256 (about 0.66 · 2^256), so a
        // random 32-byte string is a valid scalar about two times in three.
        for _ in 0..64 {
            let mut bytes = Zeroizing::new(vec![0u8; 32]);
            rng.fill(&mut bytes)?;
            if let Ok(secret) = SecretKey::from_slice(&bytes) {
                let public = secret.public_key().to_sec1_bytes().to_vec();
                return Ok(KeyPair {
                    secret: bytes,
                    public,
                });
            }
        }
        Err(CryptoError::Rng)
    }

    fn agree(&self, secret: &[u8], peer: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        let secret = SecretKey::from_slice(secret).map_err(|_| CryptoError::InvalidKey)?;
        // from_sec1_bytes refuses points not on the curve and the identity (invalid-curve
        // attacks, RFC 7518 §8.2).
        let peer = PublicKey::from_sec1_bytes(peer).map_err(|_| CryptoError::InvalidKey)?;
        let shared =
            elliptic_curve::ecdh::diffie_hellman(secret.to_nonzero_scalar(), peer.as_affine());
        Ok(Zeroizing::new(shared.raw_secret_bytes().to_vec()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registers_bp256r1_and_its_curve_once() {
        let mut registry = Registry::standard();
        assert!(registry.signature("BP256R1").is_none());
        register(&mut registry).unwrap();
        let entry = registry.signature("BP256R1").unwrap();
        assert_eq!(entry.curve, Some(BP_256));
        assert_eq!(registry.curve("BP-256").map(|c| c.coordinate_len), Some(32));
        assert_eq!(
            register(&mut registry),
            Err(RegistryError::Duplicate("BP-256"))
        );
    }
}
