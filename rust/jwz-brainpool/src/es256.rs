//! `ES256` on brainpoolP256r1, as ePA uses it.

use alloc::string::String;
use alloc::vec::Vec;

use jwz::crypto::{CryptoError, Ecdsa, Rng};
use jwz::jwa::SignatureAlgorithm;
use jwz::jwk::{EcKey, Jwk, KeyMaterial, Secret};
use jwz::keys::{JwsKey, Signature};

use crate::{BP_256, Bp256};

/// A brainpoolP256r1 key for the JWS algorithm `ES256` (ECDSA with SHA-256, `r || s`):
/// ePA's AUT signatures. Bound to `ES256`, like every jwz key to its algorithm; usable
/// wherever jwz takes a [`Signer`](jwz::keys::Signer) or
/// [`Verifier`](jwz::keys::Verifier).
#[derive(Clone)]
pub struct BrainpoolEs256Key {
    public: Vec<u8>,
    secret: Option<Secret>,
    kid: Option<String>,
}

impl BrainpoolEs256Key {
    /// The public key with the SEC1 uncompressed point `point`, e.g. from the
    /// SubjectPublicKeyInfo of the `x5c` leaf.
    ///
    /// # Errors
    ///
    /// [`CryptoError::InvalidKey`] for a point not on brainpoolP256r1.
    pub fn from_point(point: &[u8]) -> Result<Self, jwz::Error> {
        // Refuses points not on the curve and the identity.
        crate::PublicKey::from_sec1_bytes(point).map_err(|_| CryptoError::InvalidKey)?;
        Ok(BrainpoolEs256Key {
            public: point.to_vec(),
            secret: None,
            kid: None,
        })
    }

    /// The `EC` key on `BP-256` in `jwk`, private part optional. The JWK's own `alg`, if
    /// any, must be `ES256`.
    ///
    /// # Errors
    ///
    /// [`CryptoError::InvalidKey`] for another key type or curve, another `alg`, a point
    /// not on the curve, or a private part that does not match the public one.
    pub fn from_jwk(jwk: &Jwk) -> Result<Self, jwz::Error> {
        let invalid = jwz::Error::from(CryptoError::InvalidKey);
        let KeyMaterial::Ec(k) = &jwk.material else {
            return Err(invalid);
        };
        if k.crv != BP_256.as_str()
            || jwk
                .alg
                .as_deref()
                .is_some_and(|alg| alg != SignatureAlgorithm::ES256.as_str())
            || k.x.len() != 32
            || k.y.len() != 32
        {
            return Err(invalid);
        }
        let mut key = BrainpoolEs256Key::from_point(&k.point())?;
        if let Some(d) = &k.d {
            if Bp256.public_key(d.expose())? != key.public {
                return Err(invalid);
            }
            key.secret = Some(d.clone());
        }
        key.kid.clone_from(&jwk.kid);
        Ok(key)
    }

    /// A new key from `rng`.
    ///
    /// # Errors
    ///
    /// [`CryptoError::Rng`] if the source fails.
    pub fn generate(rng: &dyn Rng) -> Result<Self, jwz::Error> {
        let pair = jwz::crypto::Ecdh::generate(&Bp256, rng)?;
        Ok(BrainpoolEs256Key {
            public: pair.public,
            secret: Some(Secret::new(pair.secret.to_vec())),
            kid: None,
        })
    }

    /// This key with the key ID `kid`.
    #[must_use]
    pub fn with_kid(mut self, kid: &str) -> Self {
        self.kid = Some(kid.into());
        self
    }

    /// The public key as a JWK (`crv` `BP-256`, `alg` `ES256`).
    pub fn public_jwk(&self) -> Jwk {
        let mut jwk = Jwk::new(KeyMaterial::Ec(EcKey::from_point(
            BP_256.as_str(),
            &self.public,
        )));
        jwk.alg = Some(SignatureAlgorithm::ES256.as_str().into());
        jwk.kid.clone_from(&self.kid);
        jwk
    }
}

impl core::fmt::Debug for BrainpoolEs256Key {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BrainpoolEs256Key")
            .field("kid", &self.kid)
            .field("private", &self.secret.is_some())
            .finish_non_exhaustive()
    }
}

impl JwsKey for BrainpoolEs256Key {
    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ES256
    }

    fn key_id(&self) -> Option<&str> {
        self.kid.as_deref()
    }
}

/// Signing needs no random source: RFC 6979 nonces.
struct NoRng;

impl Rng for NoRng {
    fn fill(&self, _: &mut [u8]) -> Result<(), CryptoError> {
        Err(CryptoError::Rng)
    }
}

impl signature::Signer<Signature> for BrainpoolEs256Key {
    fn try_sign(&self, msg: &[u8]) -> Result<Signature, signature::Error> {
        let secret = self.secret.as_ref().ok_or_else(|| {
            signature::Error::from_source(jwz::Error::from(CryptoError::InvalidKey))
        })?;
        Bp256
            .sign(secret.expose(), msg, &NoRng)
            .map(Signature::from)
            .map_err(|e| signature::Error::from_source(jwz::Error::from(e)))
    }
}

impl signature::Verifier<Signature> for BrainpoolEs256Key {
    fn verify(&self, msg: &[u8], sig: &Signature) -> Result<(), signature::Error> {
        Bp256
            .verify(&self.public, msg, sig.as_bytes())
            .map_err(|e| signature::Error::from_source(jwz::Error::from(e)))
    }
}
