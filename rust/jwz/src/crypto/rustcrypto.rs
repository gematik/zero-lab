//! The pure-Rust backend on the RustCrypto 0.14 line (feature `crypto-rustcrypto`).
//!
//! Each primitive is one call into a RustCrypto crate; this module only converts between
//! JOSE byte encodings and the crates' types and maps their errors to [`CryptoError`].
//! It implements P-256 (ECDSA with SHA-256, ECDH), Ed25519, AES-GCM, AES Key Wrap,
//! SHA-2 and, with the `hmac` feature, HMAC.

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;

use aes_gcm::AesGcm;
use aes_gcm::aead::{AeadInOut, KeyInit, Nonce, Tag};
use aes_gcm::aes::{Aes128, Aes192, Aes256};
use aes_kw::{KwAes128, KwAes192, KwAes256};
use p256::ecdsa::signature::{Signer as _, Verifier as _};

use super::{
    Aead, Backend, CryptoError, Ecdh, Ecdsa, EdDsa, Hash, KeyPair, KeyWrap, Mac, Rng, Sealed,
    Zeroizing,
};
use crate::jwa::{ContentEncryptionAlgorithm, Curve, HashAlgorithm};

/// The RustCrypto backend. The random source is the operating system's (through
/// `getrandom`; `Crypto.getRandomValues` in a browser) unless one is supplied. It is
/// `Send + Sync`, so one backend can serve every thread of a server.
pub struct RustCrypto {
    rng: Box<dyn Rng + Send + Sync>,
}

impl Default for RustCrypto {
    fn default() -> Self {
        RustCrypto {
            rng: Box::new(SystemRng),
        }
    }
}

impl RustCrypto {
    /// The backend with the operating system's random source.
    pub fn new() -> Self {
        RustCrypto::default()
    }

    /// The backend with `rng` as its only source of randomness: a fixed source in
    /// tests, or the platform's source where `getrandom` has none.
    pub fn with_rng(rng: Box<dyn Rng + Send + Sync>) -> Self {
        RustCrypto { rng }
    }
}

impl Backend for RustCrypto {
    fn rng(&self) -> &dyn Rng {
        self.rng.as_ref()
    }

    fn hash(&self, alg: HashAlgorithm) -> Option<&dyn Hash> {
        match alg {
            HashAlgorithm::Sha256 => Some(&Sha2(HashAlgorithm::Sha256)),
            HashAlgorithm::Sha384 => Some(&Sha2(HashAlgorithm::Sha384)),
            HashAlgorithm::Sha512 => Some(&Sha2(HashAlgorithm::Sha512)),
        }
    }

    #[cfg(feature = "hmac")]
    fn mac(&self, alg: HashAlgorithm) -> Option<&dyn Mac> {
        match alg {
            HashAlgorithm::Sha256 => Some(&Hmac(HashAlgorithm::Sha256)),
            HashAlgorithm::Sha384 => Some(&Hmac(HashAlgorithm::Sha384)),
            HashAlgorithm::Sha512 => Some(&Hmac(HashAlgorithm::Sha512)),
        }
    }

    #[cfg(not(feature = "hmac"))]
    fn mac(&self, _: HashAlgorithm) -> Option<&dyn Mac> {
        None
    }

    fn ecdsa(&self, curve: Curve) -> Option<&dyn Ecdsa> {
        (curve == Curve::P256).then_some(&P256 as &dyn Ecdsa)
    }

    fn eddsa(&self, curve: Curve) -> Option<&dyn EdDsa> {
        (curve == Curve::ED25519).then_some(&Ed25519 as &dyn EdDsa)
    }

    fn ecdh(&self, curve: Curve) -> Option<&dyn Ecdh> {
        (curve == Curve::P256).then_some(&P256 as &dyn Ecdh)
    }

    fn aead(&self, enc: ContentEncryptionAlgorithm) -> Option<&dyn Aead> {
        match enc {
            e if e == ContentEncryptionAlgorithm::A128GCM => Some(&AesGcmCipher(16)),
            e if e == ContentEncryptionAlgorithm::A192GCM => Some(&AesGcmCipher(24)),
            e if e == ContentEncryptionAlgorithm::A256GCM => Some(&AesGcmCipher(32)),
            _ => None,
        }
    }

    fn key_wrap(&self, kek_len: usize) -> Option<&dyn KeyWrap> {
        match kek_len {
            16 => Some(&AesKeyWrap(16)),
            24 => Some(&AesKeyWrap(24)),
            32 => Some(&AesKeyWrap(32)),
            _ => None,
        }
    }
}

/// The operating system's random source.
struct SystemRng;

impl Rng for SystemRng {
    fn fill(&self, dest: &mut [u8]) -> Result<(), CryptoError> {
        getrandom::fill(dest).map_err(|_| CryptoError::Rng)
    }
}

struct Sha2(HashAlgorithm);

impl Hash for Sha2 {
    fn algorithm(&self) -> HashAlgorithm {
        self.0
    }

    fn digest(&self, parts: &[&[u8]]) -> Vec<u8> {
        fn run<D: sha2::Digest>(parts: &[&[u8]]) -> Vec<u8> {
            let mut hasher = D::new();
            for part in parts {
                hasher.update(part);
            }
            hasher.finalize().to_vec()
        }
        match self.0 {
            HashAlgorithm::Sha256 => run::<sha2::Sha256>(parts),
            HashAlgorithm::Sha384 => run::<sha2::Sha384>(parts),
            HashAlgorithm::Sha512 => run::<sha2::Sha512>(parts),
        }
    }
}

#[cfg(feature = "hmac")]
struct Hmac(HashAlgorithm);

#[cfg(feature = "hmac")]
impl Mac for Hmac {
    fn hash(&self) -> HashAlgorithm {
        self.0
    }

    fn compute(&self, key: &[u8], parts: &[&[u8]]) -> Result<Vec<u8>, CryptoError> {
        fn run<M: hmac::Mac + hmac::digest::KeyInit>(
            key: &[u8],
            parts: &[&[u8]],
        ) -> Result<Vec<u8>, CryptoError> {
            let mut mac = <M as hmac::digest::KeyInit>::new_from_slice(key)
                .map_err(|_| CryptoError::InvalidKey)?;
            for part in parts {
                mac.update(part);
            }
            Ok(mac.finalize().into_bytes().to_vec())
        }
        match self.0 {
            HashAlgorithm::Sha256 => run::<hmac::Hmac<sha2::Sha256>>(key, parts),
            HashAlgorithm::Sha384 => run::<hmac::Hmac<sha2::Sha384>>(key, parts),
            HashAlgorithm::Sha512 => run::<hmac::Hmac<sha2::Sha512>>(key, parts),
        }
    }

    fn verify(&self, key: &[u8], parts: &[&[u8]], tag: &[u8]) -> Result<(), CryptoError> {
        use subtle::ConstantTimeEq;
        let expected = Zeroizing::new(self.compute(key, parts)?);
        // Constant time: a MAC comparison must not reveal how many bytes matched.
        if expected.len() == tag.len() && bool::from(expected.ct_eq(tag)) {
            Ok(())
        } else {
            Err(CryptoError::VerificationFailed)
        }
    }
}

/// P-256: ECDSA with SHA-256 (ES256, RFC 7518 §3.4) and ECDH (RFC 7518 §4.6).
struct P256;

impl Ecdsa for P256 {
    fn curve(&self) -> Curve {
        Curve::P256
    }

    fn hash(&self) -> HashAlgorithm {
        HashAlgorithm::Sha256
    }

    fn public_key(&self, secret: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let key = p256::SecretKey::from_slice(secret).map_err(|_| CryptoError::InvalidKey)?;
        Ok(key.public_key().to_sec1_bytes().to_vec())
    }

    fn sign(&self, secret: &[u8], msg: &[u8], _rng: &dyn Rng) -> Result<Vec<u8>, CryptoError> {
        // RFC 6979 deterministic nonces: signing needs no randomness, so `rng` is unused.
        let key =
            p256::ecdsa::SigningKey::from_slice(secret).map_err(|_| CryptoError::InvalidKey)?;
        let signature: p256::ecdsa::Signature = key.sign(msg);
        Ok(signature.to_bytes().to_vec())
    }

    fn verify(&self, public: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), CryptoError> {
        let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(public)
            .map_err(|_| CryptoError::InvalidKey)?;
        // RFC 7518 §3.4: r || s, 32 bytes each; anything else is not an ES256 signature.
        let signature =
            p256::ecdsa::Signature::from_slice(sig).map_err(|_| CryptoError::VerificationFailed)?;
        key.verify(msg, &signature)
            .map_err(|_| CryptoError::VerificationFailed)
    }
}

impl Ecdh for P256 {
    fn curve(&self) -> Curve {
        Curve::P256
    }

    fn generate(&self, rng: &dyn Rng) -> Result<KeyPair, CryptoError> {
        // Rejection sampling: a 32-byte string is a valid scalar with probability
        // 1 - 2^-32; retry the rare one that is zero or not below the order.
        for _ in 0..8 {
            let mut bytes = Zeroizing::new(vec![0u8; 32]);
            rng.fill(&mut bytes)?;
            if let Ok(secret) = p256::SecretKey::from_slice(&bytes) {
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
        let secret = p256::SecretKey::from_slice(secret).map_err(|_| CryptoError::InvalidKey)?;
        // from_sec1_bytes rejects points not on the curve and the identity, the
        // invalid-curve attacks of RFC 7518 §8.2 / SP 800-56A §5.6.2.3.
        let peer = p256::PublicKey::from_sec1_bytes(peer).map_err(|_| CryptoError::InvalidKey)?;
        let shared = p256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), peer.as_affine());
        Ok(Zeroizing::new(shared.raw_secret_bytes().to_vec()))
    }
}

/// Ed25519 (RFC 8032, RFC 8037 §3.1).
struct Ed25519;

impl Ed25519 {
    fn signing_key(secret: &[u8]) -> Result<ed25519_dalek::SigningKey, CryptoError> {
        let bytes: &[u8; 32] = secret.try_into().map_err(|_| CryptoError::InvalidKey)?;
        Ok(ed25519_dalek::SigningKey::from_bytes(bytes))
    }
}

impl EdDsa for Ed25519 {
    fn curve(&self) -> Curve {
        Curve::ED25519
    }

    fn public_key(&self, secret: &[u8]) -> Result<Vec<u8>, CryptoError> {
        Ok(Self::signing_key(secret)?
            .verifying_key()
            .to_bytes()
            .to_vec())
    }

    fn sign(&self, secret: &[u8], msg: &[u8]) -> Result<Vec<u8>, CryptoError> {
        use ed25519_dalek::Signer as _;
        Ok(Self::signing_key(secret)?.sign(msg).to_bytes().to_vec())
    }

    fn verify(&self, public: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), CryptoError> {
        let public: &[u8; 32] = public.try_into().map_err(|_| CryptoError::InvalidKey)?;
        let key =
            ed25519_dalek::VerifyingKey::from_bytes(public).map_err(|_| CryptoError::InvalidKey)?;
        let signature = ed25519_dalek::Signature::from_slice(sig)
            .map_err(|_| CryptoError::VerificationFailed)?;
        // Strict verification: rejects small-order keys and non-canonical encodings,
        // so a signature has exactly one valid form.
        key.verify_strict(msg, &signature)
            .map_err(|_| CryptoError::VerificationFailed)
    }
}

/// AES-GCM with a 96-bit IV and 128-bit tag (RFC 7518 §5.3), keyed by its length.
struct AesGcmCipher(usize);

impl AesGcmCipher {
    fn seal_with<C: AeadInOut + KeyInit>(
        key: &[u8],
        iv: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Sealed, CryptoError> {
        let cipher = C::new_from_slice(key).map_err(|_| CryptoError::InvalidKey)?;
        let nonce = Nonce::<C>::try_from(iv).map_err(|_| CryptoError::InvalidInput)?;
        let mut buffer = plaintext.to_vec();
        let tag = cipher
            .encrypt_inout_detached(&nonce, aad, buffer.as_mut_slice().into())
            .map_err(|_| CryptoError::InvalidInput)?;
        Ok(Sealed {
            ciphertext: buffer,
            tag: tag.to_vec(),
        })
    }

    fn open_with<C: AeadInOut + KeyInit>(
        key: &[u8],
        iv: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
        tag: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        let cipher = C::new_from_slice(key).map_err(|_| CryptoError::InvalidKey)?;
        let nonce = Nonce::<C>::try_from(iv).map_err(|_| CryptoError::InvalidInput)?;
        let tag = Tag::<C>::try_from(tag).map_err(|_| CryptoError::VerificationFailed)?;
        let mut buffer = Zeroizing::new(ciphertext.to_vec());
        cipher
            .decrypt_inout_detached(&nonce, aad, buffer.as_mut_slice().into(), &tag)
            .map_err(|_| CryptoError::VerificationFailed)?;
        Ok(buffer)
    }
}

type Aes128Gcm = AesGcm<Aes128, aes_gcm::aead::consts::U12>;
type Aes192Gcm = AesGcm<Aes192, aes_gcm::aead::consts::U12>;
type Aes256Gcm = AesGcm<Aes256, aes_gcm::aead::consts::U12>;

impl Aead for AesGcmCipher {
    fn enc(&self) -> ContentEncryptionAlgorithm {
        match self.0 {
            16 => ContentEncryptionAlgorithm::A128GCM,
            24 => ContentEncryptionAlgorithm::A192GCM,
            _ => ContentEncryptionAlgorithm::A256GCM,
        }
    }

    fn seal(
        &self,
        key: &[u8],
        iv: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Sealed, CryptoError> {
        match self.0 {
            16 => Self::seal_with::<Aes128Gcm>(key, iv, aad, plaintext),
            24 => Self::seal_with::<Aes192Gcm>(key, iv, aad, plaintext),
            32 => Self::seal_with::<Aes256Gcm>(key, iv, aad, plaintext),
            _ => Err(CryptoError::Unsupported),
        }
    }

    fn open(
        &self,
        key: &[u8],
        iv: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
        tag: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        match self.0 {
            16 => Self::open_with::<Aes128Gcm>(key, iv, aad, ciphertext, tag),
            24 => Self::open_with::<Aes192Gcm>(key, iv, aad, ciphertext, tag),
            32 => Self::open_with::<Aes256Gcm>(key, iv, aad, ciphertext, tag),
            _ => Err(CryptoError::Unsupported),
        }
    }
}

/// AES Key Wrap (RFC 3394) with a 128, 192 or 256-bit key.
struct AesKeyWrap(usize);

impl KeyWrap for AesKeyWrap {
    fn kek_len(&self) -> usize {
        self.0
    }

    fn wrap(&self, kek: &[u8], cek: &[u8]) -> Result<Vec<u8>, CryptoError> {
        // RFC 3394 §2: the key data is n >= 2 64-bit blocks; aes-kw alone accepts less.
        if cek.len() < 16 || !cek.len().is_multiple_of(8) {
            return Err(CryptoError::InvalidInput);
        }
        let mut out = vec![0u8; cek.len() + 8];
        let len = match self.0 {
            16 => KwAes128::new_from_slice(kek)
                .map_err(|_| CryptoError::InvalidKey)?
                .wrap_key(cek, &mut out)
                .map_err(|_| CryptoError::InvalidInput)?
                .len(),
            24 => KwAes192::new_from_slice(kek)
                .map_err(|_| CryptoError::InvalidKey)?
                .wrap_key(cek, &mut out)
                .map_err(|_| CryptoError::InvalidInput)?
                .len(),
            32 => KwAes256::new_from_slice(kek)
                .map_err(|_| CryptoError::InvalidKey)?
                .wrap_key(cek, &mut out)
                .map_err(|_| CryptoError::InvalidInput)?
                .len(),
            _ => return Err(CryptoError::Unsupported),
        };
        out.truncate(len);
        Ok(out)
    }

    fn unwrap(&self, kek: &[u8], wrapped: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        // RFC 3394 §2: n >= 2 blocks plus the 64-bit integrity check value.
        if wrapped.len() < 24 || !wrapped.len().is_multiple_of(8) {
            return Err(CryptoError::InvalidInput);
        }
        let mut out = Zeroizing::new(vec![0u8; wrapped.len().saturating_sub(8)]);
        let len = match self.0 {
            16 => KwAes128::new_from_slice(kek)
                .map_err(|_| CryptoError::InvalidKey)?
                .unwrap_key(wrapped, &mut out)
                .map_err(|_| CryptoError::VerificationFailed)?
                .len(),
            24 => KwAes192::new_from_slice(kek)
                .map_err(|_| CryptoError::InvalidKey)?
                .unwrap_key(wrapped, &mut out)
                .map_err(|_| CryptoError::VerificationFailed)?
                .len(),
            32 => KwAes256::new_from_slice(kek)
                .map_err(|_| CryptoError::InvalidKey)?
                .unwrap_key(wrapped, &mut out)
                .map_err(|_| CryptoError::VerificationFailed)?
                .len(),
            _ => return Err(CryptoError::Unsupported),
        };
        out.truncate(len);
        Ok(out)
    }
}
