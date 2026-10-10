//! Async counterparts of the primitive traits, for backends that cannot answer at once:
//! WebCrypto in a browser, an HSM over PKCS#11, a cloud KMS.
//!
//! Every synchronous primitive is also an asynchronous one through [`Blocking`], and
//! every [`Backend`] is an [`AsyncBackend`], so code written against the async traits
//! runs on either. The futures are boxed (`dyn`-compatible, no runtime assumed) and
//! not `Send`, because a browser has no threads; a server that needs `Send` wraps its
//! backend at its own layer.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::future::{Future, ready};
use core::pin::Pin;

use super::{
    Aead, Backend, CryptoError, Ecdh, Ecdsa, EdDsa, Hash, KeyPair, KeyWrap, Mac, Rng, Sealed,
    Zeroizing,
};
use crate::jwa::{ContentEncryptionAlgorithm, Curve, HashAlgorithm};

/// The future an async primitive returns.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;

/// Async [`Hash`].
pub trait AsyncHash {
    /// Which hash this is.
    fn algorithm(&self) -> HashAlgorithm;
    /// See [`Hash::digest`].
    fn digest<'a>(&'a self, parts: &'a [&'a [u8]]) -> BoxFuture<'a, Vec<u8>>;
}

/// Async [`Mac`].
pub trait AsyncMac {
    /// The hash it is built on.
    fn hash(&self) -> HashAlgorithm;
    /// See [`Mac::compute`].
    fn compute<'a>(
        &'a self,
        key: &'a [u8],
        parts: &'a [&'a [u8]],
    ) -> BoxFuture<'a, Result<Vec<u8>, CryptoError>>;
    /// See [`Mac::verify`].
    fn verify<'a>(
        &'a self,
        key: &'a [u8],
        parts: &'a [&'a [u8]],
        tag: &'a [u8],
    ) -> BoxFuture<'a, Result<(), CryptoError>>;
}

/// Async [`Ecdsa`].
pub trait AsyncEcdsa {
    /// The curve.
    fn curve(&self) -> Curve;
    /// The hash signatures are computed over.
    fn hash(&self) -> HashAlgorithm;
    /// See [`Ecdsa::sign`].
    fn sign<'a>(
        &'a self,
        secret: &'a [u8],
        msg: &'a [u8],
        rng: &'a dyn Rng,
    ) -> BoxFuture<'a, Result<Vec<u8>, CryptoError>>;
    /// See [`Ecdsa::verify`].
    fn verify<'a>(
        &'a self,
        public: &'a [u8],
        msg: &'a [u8],
        sig: &'a [u8],
    ) -> BoxFuture<'a, Result<(), CryptoError>>;
}

/// Async [`EdDsa`].
pub trait AsyncEdDsa {
    /// The curve.
    fn curve(&self) -> Curve;
    /// See [`EdDsa::sign`].
    fn sign<'a>(
        &'a self,
        secret: &'a [u8],
        msg: &'a [u8],
    ) -> BoxFuture<'a, Result<Vec<u8>, CryptoError>>;
    /// See [`EdDsa::verify`].
    fn verify<'a>(
        &'a self,
        public: &'a [u8],
        msg: &'a [u8],
        sig: &'a [u8],
    ) -> BoxFuture<'a, Result<(), CryptoError>>;
}

/// Async [`Ecdh`].
pub trait AsyncEcdh {
    /// The curve.
    fn curve(&self) -> Curve;
    /// See [`Ecdh::generate`].
    fn generate<'a>(&'a self, rng: &'a dyn Rng) -> BoxFuture<'a, Result<KeyPair, CryptoError>>;
    /// See [`Ecdh::agree`].
    fn agree<'a>(
        &'a self,
        secret: &'a [u8],
        peer: &'a [u8],
    ) -> BoxFuture<'a, Result<Zeroizing<Vec<u8>>, CryptoError>>;
}

/// Async [`Aead`].
pub trait AsyncAead {
    /// The `enc` it implements.
    fn enc(&self) -> ContentEncryptionAlgorithm;
    /// See [`Aead::seal`].
    fn seal<'a>(
        &'a self,
        key: &'a [u8],
        iv: &'a [u8],
        aad: &'a [u8],
        plaintext: &'a [u8],
    ) -> BoxFuture<'a, Result<Sealed, CryptoError>>;
    /// See [`Aead::open`].
    fn open<'a>(
        &'a self,
        key: &'a [u8],
        iv: &'a [u8],
        aad: &'a [u8],
        ciphertext: &'a [u8],
        tag: &'a [u8],
    ) -> BoxFuture<'a, Result<Zeroizing<Vec<u8>>, CryptoError>>;
}

/// Async [`KeyWrap`].
pub trait AsyncKeyWrap {
    /// The key encryption key length in bytes.
    fn kek_len(&self) -> usize;
    /// See [`KeyWrap::wrap`].
    fn wrap<'a>(
        &'a self,
        kek: &'a [u8],
        cek: &'a [u8],
    ) -> BoxFuture<'a, Result<Vec<u8>, CryptoError>>;
    /// See [`KeyWrap::unwrap`].
    fn unwrap<'a>(
        &'a self,
        kek: &'a [u8],
        wrapped: &'a [u8],
    ) -> BoxFuture<'a, Result<Zeroizing<Vec<u8>>, CryptoError>>;
}

/// Async [`Backend`]. The accessors end in `_async` so that a type implementing both
/// traits never makes a call ambiguous.
pub trait AsyncBackend {
    /// The random source; synchronous everywhere, WebCrypto's included.
    fn rng_async(&self) -> &dyn Rng;
    /// See [`Backend::hash`].
    fn hash_async(&self, alg: HashAlgorithm) -> Option<Box<dyn AsyncHash + '_>>;
    /// See [`Backend::mac`].
    fn mac_async(&self, alg: HashAlgorithm) -> Option<Box<dyn AsyncMac + '_>>;
    /// See [`Backend::ecdsa`].
    fn ecdsa_async(&self, curve: Curve) -> Option<Box<dyn AsyncEcdsa + '_>>;
    /// See [`Backend::eddsa`].
    fn eddsa_async(&self, curve: Curve) -> Option<Box<dyn AsyncEdDsa + '_>>;
    /// See [`Backend::ecdh`].
    fn ecdh_async(&self, curve: Curve) -> Option<Box<dyn AsyncEcdh + '_>>;
    /// See [`Backend::aead`].
    fn aead_async(&self, enc: ContentEncryptionAlgorithm) -> Option<Box<dyn AsyncAead + '_>>;
    /// See [`Backend::key_wrap`].
    fn key_wrap_async(&self, kek_len: usize) -> Option<Box<dyn AsyncKeyWrap + '_>>;
}

/// A synchronous primitive used as an asynchronous one: the future is ready at once.
pub struct Blocking<'a, T: ?Sized>(pub &'a T);

impl<T: Hash + ?Sized> AsyncHash for Blocking<'_, T> {
    fn algorithm(&self) -> HashAlgorithm {
        self.0.algorithm()
    }
    fn digest<'a>(&'a self, parts: &'a [&'a [u8]]) -> BoxFuture<'a, Vec<u8>> {
        Box::pin(ready(self.0.digest(parts)))
    }
}

impl<T: Mac + ?Sized> AsyncMac for Blocking<'_, T> {
    fn hash(&self) -> HashAlgorithm {
        self.0.hash()
    }
    fn compute<'a>(
        &'a self,
        key: &'a [u8],
        parts: &'a [&'a [u8]],
    ) -> BoxFuture<'a, Result<Vec<u8>, CryptoError>> {
        Box::pin(ready(self.0.compute(key, parts)))
    }
    fn verify<'a>(
        &'a self,
        key: &'a [u8],
        parts: &'a [&'a [u8]],
        tag: &'a [u8],
    ) -> BoxFuture<'a, Result<(), CryptoError>> {
        Box::pin(ready(self.0.verify(key, parts, tag)))
    }
}

impl<T: Ecdsa + ?Sized> AsyncEcdsa for Blocking<'_, T> {
    fn curve(&self) -> Curve {
        self.0.curve()
    }
    fn hash(&self) -> HashAlgorithm {
        self.0.hash()
    }
    fn sign<'a>(
        &'a self,
        secret: &'a [u8],
        msg: &'a [u8],
        rng: &'a dyn Rng,
    ) -> BoxFuture<'a, Result<Vec<u8>, CryptoError>> {
        Box::pin(ready(self.0.sign(secret, msg, rng)))
    }
    fn verify<'a>(
        &'a self,
        public: &'a [u8],
        msg: &'a [u8],
        sig: &'a [u8],
    ) -> BoxFuture<'a, Result<(), CryptoError>> {
        Box::pin(ready(self.0.verify(public, msg, sig)))
    }
}

impl<T: EdDsa + ?Sized> AsyncEdDsa for Blocking<'_, T> {
    fn curve(&self) -> Curve {
        self.0.curve()
    }
    fn sign<'a>(
        &'a self,
        secret: &'a [u8],
        msg: &'a [u8],
    ) -> BoxFuture<'a, Result<Vec<u8>, CryptoError>> {
        Box::pin(ready(self.0.sign(secret, msg)))
    }
    fn verify<'a>(
        &'a self,
        public: &'a [u8],
        msg: &'a [u8],
        sig: &'a [u8],
    ) -> BoxFuture<'a, Result<(), CryptoError>> {
        Box::pin(ready(self.0.verify(public, msg, sig)))
    }
}

impl<T: Ecdh + ?Sized> AsyncEcdh for Blocking<'_, T> {
    fn curve(&self) -> Curve {
        self.0.curve()
    }
    fn generate<'a>(&'a self, rng: &'a dyn Rng) -> BoxFuture<'a, Result<KeyPair, CryptoError>> {
        Box::pin(ready(self.0.generate(rng)))
    }
    fn agree<'a>(
        &'a self,
        secret: &'a [u8],
        peer: &'a [u8],
    ) -> BoxFuture<'a, Result<Zeroizing<Vec<u8>>, CryptoError>> {
        Box::pin(ready(self.0.agree(secret, peer)))
    }
}

impl<T: Aead + ?Sized> AsyncAead for Blocking<'_, T> {
    fn enc(&self) -> ContentEncryptionAlgorithm {
        self.0.enc()
    }
    fn seal<'a>(
        &'a self,
        key: &'a [u8],
        iv: &'a [u8],
        aad: &'a [u8],
        plaintext: &'a [u8],
    ) -> BoxFuture<'a, Result<Sealed, CryptoError>> {
        Box::pin(ready(self.0.seal(key, iv, aad, plaintext)))
    }
    fn open<'a>(
        &'a self,
        key: &'a [u8],
        iv: &'a [u8],
        aad: &'a [u8],
        ciphertext: &'a [u8],
        tag: &'a [u8],
    ) -> BoxFuture<'a, Result<Zeroizing<Vec<u8>>, CryptoError>> {
        Box::pin(ready(self.0.open(key, iv, aad, ciphertext, tag)))
    }
}

impl<T: KeyWrap + ?Sized> AsyncKeyWrap for Blocking<'_, T> {
    fn kek_len(&self) -> usize {
        self.0.kek_len()
    }
    fn wrap<'a>(
        &'a self,
        kek: &'a [u8],
        cek: &'a [u8],
    ) -> BoxFuture<'a, Result<Vec<u8>, CryptoError>> {
        Box::pin(ready(self.0.wrap(kek, cek)))
    }
    fn unwrap<'a>(
        &'a self,
        kek: &'a [u8],
        wrapped: &'a [u8],
    ) -> BoxFuture<'a, Result<Zeroizing<Vec<u8>>, CryptoError>> {
        Box::pin(ready(self.0.unwrap(kek, wrapped)))
    }
}

impl<B: Backend> AsyncBackend for B {
    fn rng_async(&self) -> &dyn Rng {
        self.rng()
    }
    fn hash_async(&self, alg: HashAlgorithm) -> Option<Box<dyn AsyncHash + '_>> {
        let hash = self.hash(alg)?;
        Some(Box::new(Blocking(hash)))
    }
    fn mac_async(&self, alg: HashAlgorithm) -> Option<Box<dyn AsyncMac + '_>> {
        let mac = self.mac(alg)?;
        Some(Box::new(Blocking(mac)))
    }
    fn ecdsa_async(&self, curve: Curve) -> Option<Box<dyn AsyncEcdsa + '_>> {
        let ecdsa = self.ecdsa(curve)?;
        Some(Box::new(Blocking(ecdsa)))
    }
    fn eddsa_async(&self, curve: Curve) -> Option<Box<dyn AsyncEdDsa + '_>> {
        let eddsa = self.eddsa(curve)?;
        Some(Box::new(Blocking(eddsa)))
    }
    fn ecdh_async(&self, curve: Curve) -> Option<Box<dyn AsyncEcdh + '_>> {
        let ecdh = self.ecdh(curve)?;
        Some(Box::new(Blocking(ecdh)))
    }
    fn aead_async(&self, enc: ContentEncryptionAlgorithm) -> Option<Box<dyn AsyncAead + '_>> {
        let aead = self.aead(enc)?;
        Some(Box::new(Blocking(aead)))
    }
    fn key_wrap_async(&self, kek_len: usize) -> Option<Box<dyn AsyncKeyWrap + '_>> {
        let key_wrap = self.key_wrap(kek_len)?;
        Some(Box::new(Blocking(key_wrap)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A backend with only a toy hash, enough to show the sync-to-async bridge.
    struct ToyBackend;
    struct ToyHash;
    struct NoRng;

    impl Rng for NoRng {
        fn fill(&self, _: &mut [u8]) -> Result<(), CryptoError> {
            Err(CryptoError::Rng)
        }
    }

    impl Hash for ToyHash {
        fn algorithm(&self) -> HashAlgorithm {
            HashAlgorithm::Sha256
        }
        fn digest(&self, parts: &[&[u8]]) -> Vec<u8> {
            parts.iter().flat_map(|p| p.iter().copied()).rev().collect()
        }
    }

    impl Backend for ToyBackend {
        fn rng(&self) -> &dyn Rng {
            &NoRng
        }
        fn hash(&self, alg: HashAlgorithm) -> Option<&dyn Hash> {
            (alg == HashAlgorithm::Sha256).then_some(&ToyHash as &dyn Hash)
        }
        fn mac(&self, _: HashAlgorithm) -> Option<&dyn Mac> {
            None
        }
        fn ecdsa(&self, _: Curve) -> Option<&dyn Ecdsa> {
            None
        }
        fn eddsa(&self, _: Curve) -> Option<&dyn EdDsa> {
            None
        }
        fn ecdh(&self, _: Curve) -> Option<&dyn Ecdh> {
            None
        }
        fn aead(&self, _: ContentEncryptionAlgorithm) -> Option<&dyn Aead> {
            None
        }
        fn key_wrap(&self, _: usize) -> Option<&dyn KeyWrap> {
            None
        }
    }

    #[test]
    fn every_sync_backend_is_an_async_backend() {
        let backend = ToyBackend;
        let hash = backend.hash_async(HashAlgorithm::Sha256).unwrap();
        let digest = futures_lite::future::block_on(hash.digest(&[b"ab", b"c"]));
        assert_eq!(digest, b"cba");
        assert!(backend.hash_async(HashAlgorithm::Sha512).is_none());
        assert!(backend.ecdsa_async(Curve::P256).is_none());
        assert_eq!(backend.rng_async().fill(&mut [0; 4]), Err(CryptoError::Rng));
    }
}
