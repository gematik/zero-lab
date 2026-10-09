//! Keys held in memory, using any [`Backend`] for the cryptography.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use super::{JwsKey, KeyAgreement, Signature, to_signature_error};
use crate::crypto::{Backend, CryptoError, Zeroizing};
use crate::error::{Error, ErrorCode};
use crate::jwa::{Curve, HashAlgorithm, KeyType, Registry, SignatureAlgorithm, Support};
use crate::jwk::{EcKey, Jwk, KeyMaterial, OctKey, OkpKey, Secret};

/// A JWS key in memory, bound to one algorithm.
pub struct SoftwareKey<B: Backend> {
    backend: Arc<B>,
    alg: SignatureAlgorithm,
    kid: Option<String>,
    kind: Kind,
}

enum Kind {
    Ecdsa {
        curve: Curve,
        public: Vec<u8>,
        secret: Option<Secret>,
    },
    EdDsa {
        curve: Curve,
        public: Vec<u8>,
        secret: Option<Secret>,
    },
    Hmac {
        hash: HashAlgorithm,
        key: Secret,
    },
}

const MISMATCH: Error = Error::new(ErrorCode::KeyMismatch, "key for algorithm");
const UNSUPPORTED: Error = Error::new(ErrorCode::UnsupportedAlgorithm, "key for algorithm");

impl<B: Backend> SoftwareKey<B> {
    /// The key in `jwk`, for `alg`.
    ///
    /// # Errors
    ///
    /// [`ErrorCode::UnsupportedAlgorithm`] if `alg` is not registered as available or
    /// the backend lacks it; [`ErrorCode::KeyMismatch`] if the key's type, curve or own
    /// `alg` does not fit, or its private part does not match its public part; the
    /// errors of [`Jwk::check`].
    pub fn from_jwk(
        jwk: &Jwk,
        alg: SignatureAlgorithm,
        registry: &Registry,
        backend: Arc<B>,
    ) -> Result<Self, Error> {
        let entry = registry
            .signature(alg.as_str())
            .filter(|e| e.support == Support::Available)
            .ok_or(UNSUPPORTED)?;
        jwk.check(registry)?;
        // RFC 7517 §4.4: a key that names its algorithm is only for that algorithm.
        if jwk.key_type() != entry.key_type || jwk.alg.as_deref().is_some_and(|a| a != alg.as_str())
        {
            return Err(MISMATCH);
        }
        let kind = match &jwk.material {
            KeyMaterial::Ec(k) => ecdsa_kind(k, entry.curve, registry, backend.as_ref())?,
            KeyMaterial::Okp(k) => eddsa_kind(k, registry, backend.as_ref())?,
            KeyMaterial::Oct(k) => hmac_kind(k, entry.hash, backend.as_ref())?,
            KeyMaterial::Rsa(_) => return Err(UNSUPPORTED),
        };
        Ok(SoftwareKey {
            backend,
            alg,
            kid: jwk.kid.clone(),
            kind,
        })
    }

    /// A new random key for `alg`, from the backend's random source.
    ///
    /// # Errors
    ///
    /// [`ErrorCode::UnsupportedAlgorithm`], or the backend's error.
    pub fn generate(
        alg: SignatureAlgorithm,
        registry: &Registry,
        backend: Arc<B>,
    ) -> Result<Self, Error> {
        let entry = registry
            .signature(alg.as_str())
            .filter(|e| e.support == Support::Available)
            .ok_or(UNSUPPORTED)?;
        let kind = if entry.key_type == KeyType::EC {
            let curve = entry.curve.ok_or(UNSUPPORTED)?;
            let len = coordinate_len(registry, curve)?;
            let ecdsa = backend.ecdsa(curve).ok_or(UNSUPPORTED)?;
            let (secret, public) = random_scalar(backend.as_ref(), len, |s| ecdsa.public_key(s))?;
            Kind::Ecdsa {
                curve,
                public,
                secret: Some(secret),
            }
        } else if entry.key_type == KeyType::OKP {
            // EdDSA's curve comes from the key; generated keys are Ed25519.
            let curve = Curve::ED25519;
            let len = coordinate_len(registry, curve)?;
            let eddsa = backend.eddsa(curve).ok_or(UNSUPPORTED)?;
            let (secret, public) = random_scalar(backend.as_ref(), len, |s| eddsa.public_key(s))?;
            Kind::EdDsa {
                curve,
                public,
                secret: Some(secret),
            }
        } else if entry.key_type == KeyType::OCT {
            let hash = entry.hash.ok_or(UNSUPPORTED)?;
            backend.mac(hash).ok_or(UNSUPPORTED)?;
            let mut key = vec![0u8; hash.output_len()];
            backend.rng().fill(&mut key)?;
            Kind::Hmac {
                hash,
                key: Secret::new(key),
            }
        } else {
            return Err(UNSUPPORTED);
        };
        Ok(SoftwareKey {
            backend,
            alg,
            kid: None,
            kind,
        })
    }

    /// The key with `kid` as its key ID.
    #[must_use]
    pub fn with_kid(mut self, kid: impl Into<String>) -> Self {
        self.kid = Some(kid.into());
        self
    }

    /// The key as a JWK, private part included, with `alg` and `kid` set.
    pub fn to_jwk(&self) -> Jwk {
        let material = match &self.kind {
            Kind::Ecdsa {
                curve,
                public,
                secret,
            } => {
                let (x, y) = split_sec1(public);
                KeyMaterial::Ec(EcKey {
                    crv: curve.as_str().into(),
                    x,
                    y,
                    d: secret.clone(),
                })
            }
            Kind::EdDsa {
                curve,
                public,
                secret,
            } => KeyMaterial::Okp(OkpKey {
                crv: curve.as_str().into(),
                x: public.clone(),
                d: secret.clone(),
            }),
            Kind::Hmac { key, .. } => KeyMaterial::Oct(OctKey { k: key.clone() }),
        };
        let mut jwk = Jwk::new(material);
        jwk.kid.clone_from(&self.kid);
        jwk.alg = Some(self.alg.as_str().into());
        jwk
    }

    /// The public key as a JWK; for HMAC, which has no public part, the key itself.
    pub fn public_jwk(&self) -> Jwk {
        self.to_jwk().public()
    }
}

impl<B: Backend> JwsKey for SoftwareKey<B> {
    fn algorithm(&self) -> SignatureAlgorithm {
        self.alg
    }

    fn key_id(&self) -> Option<&str> {
        self.kid.as_deref()
    }
}

impl<B: Backend> signature::Signer<Signature> for SoftwareKey<B> {
    fn try_sign(&self, msg: &[u8]) -> Result<Signature, signature::Error> {
        let missing = Error::new(ErrorCode::MissingPrivateKey, "sign");
        let bytes = match &self.kind {
            Kind::Ecdsa { curve, secret, .. } => {
                let secret = secret.as_ref().ok_or(missing).map_err(to_signature_error)?;
                let ecdsa = self
                    .backend
                    .ecdsa(*curve)
                    .ok_or(UNSUPPORTED)
                    .map_err(to_signature_error)?;
                ecdsa.sign(secret.expose(), msg, self.backend.rng())
            }
            Kind::EdDsa { curve, secret, .. } => {
                let secret = secret.as_ref().ok_or(missing).map_err(to_signature_error)?;
                let eddsa = self
                    .backend
                    .eddsa(*curve)
                    .ok_or(UNSUPPORTED)
                    .map_err(to_signature_error)?;
                eddsa.sign(secret.expose(), msg)
            }
            Kind::Hmac { hash, key } => {
                let mac = self
                    .backend
                    .mac(*hash)
                    .ok_or(UNSUPPORTED)
                    .map_err(to_signature_error)?;
                mac.compute(key.expose(), &[msg])
            }
        };
        bytes
            .map(Signature::from)
            .map_err(|e| to_signature_error(Error::from(e)))
    }
}

impl<B: Backend> signature::Verifier<Signature> for SoftwareKey<B> {
    fn verify(&self, msg: &[u8], sig: &Signature) -> Result<(), signature::Error> {
        let result = match &self.kind {
            Kind::Ecdsa { curve, public, .. } => self
                .backend
                .ecdsa(*curve)
                .ok_or(CryptoError::Unsupported)
                .and_then(|ecdsa| ecdsa.verify(public, msg, sig.as_bytes())),
            Kind::EdDsa { curve, public, .. } => self
                .backend
                .eddsa(*curve)
                .ok_or(CryptoError::Unsupported)
                .and_then(|eddsa| eddsa.verify(public, msg, sig.as_bytes())),
            // RFC 7518 §3.2: compare the MAC in constant time (Mac::verify does).
            Kind::Hmac { hash, key } => self
                .backend
                .mac(*hash)
                .ok_or(CryptoError::Unsupported)
                .and_then(|mac| mac.verify(key.expose(), &[msg], sig.as_bytes())),
        };
        result.map_err(|e| to_signature_error(Error::from(e)))
    }
}

/// The private side of ECDH-ES in memory (RFC 7518 §4.6).
pub struct SoftwareAgreementKey<B: Backend> {
    backend: Arc<B>,
    curve: Curve,
    kid: Option<String>,
    public: Vec<u8>,
    secret: Secret,
}

impl<B: Backend> SoftwareAgreementKey<B> {
    /// The private EC key in `jwk`.
    ///
    /// # Errors
    ///
    /// [`ErrorCode::MissingPrivateKey`] without `d`, [`ErrorCode::KeyMismatch`] for a key
    /// that is not EC, [`ErrorCode::UnsupportedAlgorithm`] if the backend has no ECDH on
    /// its curve; the errors of [`Jwk::check`].
    pub fn from_jwk(jwk: &Jwk, registry: &Registry, backend: Arc<B>) -> Result<Self, Error> {
        jwk.check(registry)?;
        let KeyMaterial::Ec(k) = &jwk.material else {
            return Err(MISMATCH);
        };
        let curve = registry.curve(&k.crv).map(|e| e.crv).ok_or(MISMATCH)?;
        backend.ecdh(curve).ok_or(UNSUPPORTED)?;
        let secret =
            k.d.clone()
                .ok_or(Error::new(ErrorCode::MissingPrivateKey, "key agreement"))?;
        let public = sec1(&k.x, &k.y);
        if let Some(ecdsa) = backend.ecdsa(curve)
            && ecdsa.public_key(secret.expose())? != public
        {
            return Err(MISMATCH);
        }
        Ok(SoftwareAgreementKey {
            backend,
            curve,
            kid: jwk.kid.clone(),
            public,
            secret,
        })
    }

    /// A new key on `curve`.
    ///
    /// # Errors
    ///
    /// [`ErrorCode::UnsupportedAlgorithm`] without ECDH on `curve`, or the backend's error.
    pub fn generate(curve: Curve, backend: Arc<B>) -> Result<Self, Error> {
        let pair = backend
            .ecdh(curve)
            .ok_or(UNSUPPORTED)?
            .generate(backend.rng())?;
        Ok(SoftwareAgreementKey {
            backend,
            curve,
            kid: None,
            public: pair.public,
            secret: Secret::new(pair.secret.to_vec()),
        })
    }

    /// The public key as a JWK.
    pub fn public_jwk(&self) -> Jwk {
        let (x, y) = split_sec1(&self.public);
        let mut jwk = Jwk::new(KeyMaterial::Ec(EcKey {
            crv: self.curve.as_str().into(),
            x,
            y,
            d: None,
        }));
        jwk.kid.clone_from(&self.kid);
        jwk
    }
}

impl<B: Backend> KeyAgreement for SoftwareAgreementKey<B> {
    fn curve(&self) -> Curve {
        self.curve
    }

    fn key_id(&self) -> Option<&str> {
        self.kid.as_deref()
    }

    fn agree(&self, peer: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
        let ecdh = self.backend.ecdh(self.curve).ok_or(UNSUPPORTED)?;
        Ok(ecdh.agree(self.secret.expose(), peer)?)
    }
}

fn ecdsa_kind<B: Backend>(
    k: &EcKey,
    expected: Option<Curve>,
    registry: &Registry,
    backend: &B,
) -> Result<Kind, Error> {
    let curve = registry.curve(&k.crv).map(|e| e.crv).ok_or(MISMATCH)?;
    if expected != Some(curve) {
        return Err(MISMATCH);
    }
    let ecdsa = backend.ecdsa(curve).ok_or(UNSUPPORTED)?;
    let public = sec1(&k.x, &k.y);
    if let Some(d) = &k.d
        && ecdsa.public_key(d.expose())? != public
    {
        return Err(MISMATCH);
    }
    Ok(Kind::Ecdsa {
        curve,
        public,
        secret: k.d.clone(),
    })
}

fn eddsa_kind<B: Backend>(k: &OkpKey, registry: &Registry, backend: &B) -> Result<Kind, Error> {
    // RFC 8037 §3.1: EdDSA takes its curve from the key; X25519/X448 do not sign.
    let curve = registry.curve(&k.crv).map(|e| e.crv).ok_or(MISMATCH)?;
    let eddsa = backend.eddsa(curve).ok_or(MISMATCH)?;
    if let Some(d) = &k.d
        && eddsa.public_key(d.expose())? != k.x
    {
        return Err(MISMATCH);
    }
    Ok(Kind::EdDsa {
        curve,
        public: k.x.clone(),
        secret: k.d.clone(),
    })
}

fn hmac_kind<B: Backend>(
    k: &OctKey,
    hash: Option<HashAlgorithm>,
    backend: &B,
) -> Result<Kind, Error> {
    let hash = hash.ok_or(UNSUPPORTED)?;
    backend.mac(hash).ok_or(UNSUPPORTED)?;
    // RFC 7518 §3.2: a key of the same size as the hash output or larger MUST be used.
    if k.k.expose().len() < hash.output_len() {
        return Err(Error::new(ErrorCode::KeyLength, "hmac key"));
    }
    Ok(Kind::Hmac {
        hash,
        key: k.k.clone(),
    })
}

fn coordinate_len(registry: &Registry, curve: Curve) -> Result<usize, Error> {
    registry
        .curve(curve.as_str())
        .map(|e| e.coordinate_len)
        .ok_or(UNSUPPORTED)
}

/// A random private key of `len` bytes that `public_of` accepts, with its public key.
fn random_scalar<B: Backend>(
    backend: &B,
    len: usize,
    public_of: impl Fn(&[u8]) -> Result<Vec<u8>, CryptoError>,
) -> Result<(Secret, Vec<u8>), Error> {
    // A random string is a valid scalar except with negligible probability; a handful
    // of attempts only guards against a broken random source.
    for _ in 0..8 {
        let mut bytes = Zeroizing::new(vec![0u8; len]);
        backend.rng().fill(&mut bytes)?;
        if let Ok(public) = public_of(&bytes) {
            return Ok((Secret::new(bytes.to_vec()), public));
        }
    }
    Err(Error::from(CryptoError::Rng))
}

/// The SEC1 uncompressed point `0x04 || x || y`.
fn sec1(x: &[u8], y: &[u8]) -> Vec<u8> {
    let mut point = Vec::with_capacity(1 + x.len() + y.len());
    point.push(0x04);
    point.extend_from_slice(x);
    point.extend_from_slice(y);
    point
}

/// `x` and `y` of a SEC1 uncompressed point.
fn split_sec1(point: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let coordinates = point.get(1..).unwrap_or_default();
    let (x, y) = coordinates.split_at(coordinates.len() / 2);
    (x.to_vec(), y.to_vec())
}
