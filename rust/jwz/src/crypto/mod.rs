//! The cryptographic primitives jwz uses, as traits: [`Rng`], [`Hash`], [`Mac`],
//! [`Ecdsa`], [`EdDsa`], [`Ecdh`], [`Aead`] and [`KeyWrap`], gathered by a [`Backend`].
//!
//! Nothing in jwz calls a cryptographic library directly; JWS, JWE and keys reach every
//! primitive through these traits, and a backend supplies them. The pure-Rust backend
//! (RustCrypto 0.14 line) is the `crypto-rustcrypto` feature; other backends, such as
//! WebCrypto in a browser or aws-lc for a FIPS path, are crates of their own that
//! implement the same traits, so jwz's dependency tree never contains them
//! (ADR 0001, key point 1).
//!
//! The traits work on bytes in the JOSE encodings: public EC keys as SEC1 uncompressed
//! points, EC private keys as big-endian scalars, ECDSA signatures as `r || s`
//! (RFC 7518 §3.4), Edwards keys and signatures as RFC 8032 bytes. Secret outputs come
//! back in [`Zeroizing`] buffers.
//!
//! The Concat KDF of ECDH-ES (RFC 7518 §4.6.2) is not a backend primitive: jwz
//! implements it once, over the backend's [`Hash`], so the code that turns a shared
//! secret into a key is the same for every backend and is the code that is verified.
//!
//! Each trait has an async counterpart in [`asynchronous`], because WebCrypto, HSMs and
//! cloud KMS answer asynchronously; every synchronous backend is also an asynchronous one.

pub mod asynchronous;

use alloc::vec::Vec;
use core::fmt;

pub use zeroize::Zeroizing;

use crate::jwa::{ContentEncryptionAlgorithm, Curve, HashAlgorithm};

/// Why a primitive failed. Deliberately coarse: it never carries key material, token
/// contents or which check inside a primitive failed (ADR 0001, auditability).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum CryptoError {
    /// The backend does not implement this primitive or parameter set.
    Unsupported,
    /// A key has the wrong length or is not a valid point or scalar.
    InvalidKey,
    /// An input other than a key has the wrong length or form.
    InvalidInput,
    /// A signature, MAC or authentication tag does not verify.
    VerificationFailed,
    /// The random source failed.
    Rng,
    /// The backend failed for another reason (an HSM or WebCrypto error, say).
    Backend,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            CryptoError::Unsupported => "unsupported by the crypto backend",
            CryptoError::InvalidKey => "invalid key",
            CryptoError::InvalidInput => "invalid input",
            CryptoError::VerificationFailed => "verification failed",
            CryptoError::Rng => "random source failed",
            CryptoError::Backend => "crypto backend failed",
        })
    }
}

impl core::error::Error for CryptoError {}

/// A cryptographically secure random source. The only way randomness enters jwz, so a
/// test can replace it with a fixed source and every path stays reproducible.
pub trait Rng {
    /// Fills `dest` with random bytes.
    ///
    /// # Errors
    ///
    /// [`CryptoError::Rng`] if the source fails.
    fn fill(&self, dest: &mut [u8]) -> Result<(), CryptoError>;
}

/// A hash function.
pub trait Hash {
    /// Which hash this is.
    fn algorithm(&self) -> HashAlgorithm;
    /// The digest of the concatenation of `parts`.
    fn digest(&self, parts: &[&[u8]]) -> Vec<u8>;
}

/// HMAC (RFC 2104) over one hash.
pub trait Mac {
    /// The hash it is built on.
    fn hash(&self) -> HashAlgorithm;
    /// The MAC of the concatenation of `parts` under `key`.
    ///
    /// # Errors
    ///
    /// [`CryptoError::InvalidKey`] for a key the backend refuses.
    fn compute(&self, key: &[u8], parts: &[&[u8]]) -> Result<Vec<u8>, CryptoError>;
    /// Checks `tag` against the MAC of `parts`, in constant time.
    ///
    /// # Errors
    ///
    /// [`CryptoError::VerificationFailed`] if it does not match.
    fn verify(&self, key: &[u8], parts: &[&[u8]], tag: &[u8]) -> Result<(), CryptoError>;
}

/// ECDSA on one curve, with the hash the JWS algorithm prescribes for it.
pub trait Ecdsa {
    /// The curve.
    fn curve(&self) -> Curve;
    /// The hash signatures are computed over.
    fn hash(&self) -> HashAlgorithm;
    /// The SEC1 uncompressed public point of the private scalar `secret`.
    ///
    /// # Errors
    ///
    /// [`CryptoError::InvalidKey`] if `secret` is not a valid scalar.
    fn public_key(&self, secret: &[u8]) -> Result<Vec<u8>, CryptoError>;
    /// Signs `msg` with the private scalar `secret`; the signature is `r || s`, each
    /// left-padded to the curve's coordinate length (RFC 7518 §3.4).
    ///
    /// # Errors
    ///
    /// [`CryptoError::InvalidKey`], or [`CryptoError::Rng`] where signing is randomized.
    fn sign(&self, secret: &[u8], msg: &[u8], rng: &dyn Rng) -> Result<Vec<u8>, CryptoError>;
    /// Verifies the `r || s` signature `sig` over `msg` under the SEC1 point `public`.
    ///
    /// # Errors
    ///
    /// [`CryptoError::InvalidKey`] for a point not on the curve,
    /// [`CryptoError::VerificationFailed`] for a signature that does not verify.
    fn verify(&self, public: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), CryptoError>;
}

/// EdDSA (RFC 8032) on one curve.
pub trait EdDsa {
    /// The curve (`Ed25519`).
    fn curve(&self) -> Curve;
    /// The public key of the private key `secret`.
    ///
    /// # Errors
    ///
    /// [`CryptoError::InvalidKey`] for a secret of the wrong length.
    fn public_key(&self, secret: &[u8]) -> Result<Vec<u8>, CryptoError>;
    /// Signs `msg`.
    ///
    /// # Errors
    ///
    /// [`CryptoError::InvalidKey`] for a secret of the wrong length.
    fn sign(&self, secret: &[u8], msg: &[u8]) -> Result<Vec<u8>, CryptoError>;
    /// Verifies `sig` over `msg` under `public`.
    ///
    /// # Errors
    ///
    /// [`CryptoError::InvalidKey`] or [`CryptoError::VerificationFailed`].
    fn verify(&self, public: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), CryptoError>;
}

/// A freshly generated key pair, for the ephemeral key of ECDH-ES.
pub struct KeyPair {
    /// The private scalar.
    pub secret: Zeroizing<Vec<u8>>,
    /// The SEC1 uncompressed public point.
    pub public: Vec<u8>,
}

/// Elliptic-curve Diffie-Hellman on one curve.
pub trait Ecdh {
    /// The curve.
    fn curve(&self) -> Curve;
    /// A new key pair from `rng`.
    ///
    /// # Errors
    ///
    /// [`CryptoError::Rng`] if the source fails.
    fn generate(&self, rng: &dyn Rng) -> Result<KeyPair, CryptoError>;
    /// The shared secret Z, the x-coordinate of `secret · peer` (SP 800-56A §5.7.1.2),
    /// after checking that `peer` is a valid point on the curve.
    ///
    /// # Errors
    ///
    /// [`CryptoError::InvalidKey`] for an invalid scalar or a point not on the curve.
    fn agree(&self, secret: &[u8], peer: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError>;
}

/// The output of an AEAD encryption.
pub struct Sealed {
    /// The ciphertext, as long as the plaintext.
    pub ciphertext: Vec<u8>,
    /// The authentication tag.
    pub tag: Vec<u8>,
}

/// An AEAD content cipher (RFC 7518 §5.3).
pub trait Aead {
    /// The `enc` it implements.
    fn enc(&self) -> ContentEncryptionAlgorithm;
    /// Encrypts `plaintext` under `key` and `iv`, authenticating `aad`.
    ///
    /// # Errors
    ///
    /// [`CryptoError::InvalidKey`] or [`CryptoError::InvalidInput`] for wrong lengths.
    fn seal(
        &self,
        key: &[u8],
        iv: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Sealed, CryptoError>;
    /// Decrypts and authenticates; nothing is returned unless the tag verifies.
    ///
    /// # Errors
    ///
    /// [`CryptoError::VerificationFailed`] if the tag does not verify.
    fn open(
        &self,
        key: &[u8],
        iv: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
        tag: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError>;
}

/// AES Key Wrap (RFC 3394) with one key length.
pub trait KeyWrap {
    /// The key encryption key length in bytes (16, 24 or 32).
    fn kek_len(&self) -> usize;
    /// Wraps `cek` under `kek`.
    ///
    /// # Errors
    ///
    /// [`CryptoError::InvalidKey`] or [`CryptoError::InvalidInput`] for wrong lengths.
    fn wrap(&self, kek: &[u8], cek: &[u8]) -> Result<Vec<u8>, CryptoError>;
    /// Unwraps `wrapped`; fails unless the integrity check of RFC 3394 §2.2.3 holds.
    ///
    /// # Errors
    ///
    /// [`CryptoError::VerificationFailed`] if the integrity check fails.
    fn unwrap(&self, kek: &[u8], wrapped: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError>;
}

/// A complete set of primitives. Every accessor returns `None` for what the backend
/// does not implement, and jwz then reports [`CryptoError::Unsupported`].
pub trait Backend {
    /// The random source.
    fn rng(&self) -> &dyn Rng;
    /// The hash function `alg`.
    fn hash(&self, alg: HashAlgorithm) -> Option<&dyn Hash>;
    /// HMAC over `alg`.
    fn mac(&self, alg: HashAlgorithm) -> Option<&dyn Mac>;
    /// ECDSA on `curve`.
    fn ecdsa(&self, curve: Curve) -> Option<&dyn Ecdsa>;
    /// EdDSA on `curve`.
    fn eddsa(&self, curve: Curve) -> Option<&dyn EdDsa>;
    /// ECDH on `curve`.
    fn ecdh(&self, curve: Curve) -> Option<&dyn Ecdh>;
    /// The content cipher `enc`.
    fn aead(&self, enc: ContentEncryptionAlgorithm) -> Option<&dyn Aead>;
    /// AES Key Wrap with a `kek_len`-byte key.
    fn key_wrap(&self, kek_len: usize) -> Option<&dyn KeyWrap>;
}
