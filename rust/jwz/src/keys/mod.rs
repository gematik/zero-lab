//! Keys as traits: [`Signer`], [`Verifier`], [`KeyAgreement`] and their async forms.
//! JWS and JWE only ever talk to these traits, so a key can live anywhere: in memory
//! ([`SoftwareKey`]), in an HSM or smartcard, in WebCrypto, behind a cloud KMS. Nothing
//! in jwz needs private key bytes except the software keys themselves (ADR 0001, key
//! point 4).
//!
//! A key is bound to one algorithm ([`JwsKey::algorithm`]): it signs and verifies only
//! with that algorithm, so the token header can never choose another one for it.
//!
//! The synchronous traits come from RustCrypto's `signature` crate: anything that
//! implements `signature::Signer<Signature>` and [`JwsKey`] is a jwz [`Signer`], and
//! likewise for verifiers. Every [`Signer`] is also an [`AsyncSigner`]. A key that can
//! only answer asynchronously implements [`AsyncSigner`] directly:
//!
//! ```
//! use jwz::crypto::asynchronous::BoxFuture;
//! use jwz::jwa::SignatureAlgorithm;
//! use jwz::keys::{AsyncSigner, JwsKey, Signature};
//!
//! /// A key that never leaves the HSM: the signer holds a handle and a client.
//! struct HsmKey<'c> {
//!     client: &'c HsmClient,
//!     handle: u64,
//! }
//!
//! # struct HsmClient;
//! # impl HsmClient {
//! #     async fn sign_es256(&self, _handle: u64, _msg: &[u8]) -> Result<Vec<u8>, ()> {
//! #         Ok(vec![0; 64])
//! #     }
//! # }
//! impl JwsKey for HsmKey<'_> {
//!     fn algorithm(&self) -> SignatureAlgorithm {
//!         SignatureAlgorithm::ES256
//!     }
//! }
//!
//! impl AsyncSigner for HsmKey<'_> {
//!     fn sign_async<'a>(&'a self, msg: &'a [u8]) -> BoxFuture<'a, Result<Signature, jwz::Error>> {
//!         Box::pin(async move {
//!             let raw = self
//!                 .client
//!                 .sign_es256(self.handle, msg)
//!                 .await
//!                 .map_err(|()| jwz::crypto::CryptoError::Backend)?;
//!             Ok(Signature::from(raw))
//!         })
//!     }
//! }
//! ```

mod software;
#[cfg(feature = "test-util")]
mod test_util;

use alloc::boxed::Box;
use alloc::vec::Vec;

#[cfg(feature = "jwe")]
pub use software::SymmetricKey;
pub use software::{SoftwareAgreementKey, SoftwareKey};
#[cfg(feature = "test-util")]
pub use test_util::{FixedRng, MockHsm, MockHsmSigner, TestKms, TestKmsSigner};

use crate::crypto::Zeroizing;
use crate::crypto::asynchronous::BoxFuture;
use crate::error::Error;
use crate::jwa::{Curve, SignatureAlgorithm};

/// A JWS signature value: the bytes the algorithm defines (`r || s` for ECDSA,
/// RFC 7518 §3.4; RFC 8032 bytes for EdDSA; the MAC for HMAC).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature(Vec<u8>);

impl Signature {
    /// The signature bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for Signature {
    fn from(bytes: Vec<u8>) -> Self {
        Signature(bytes)
    }
}

impl TryFrom<&[u8]> for Signature {
    type Error = signature::Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Ok(Signature(bytes.to_vec()))
    }
}

impl From<Signature> for Vec<u8> {
    fn from(signature: Signature) -> Self {
        signature.0
    }
}

impl signature::SignatureEncoding for Signature {
    type Repr = Vec<u8>;
}

/// What a JWS key is for: its algorithm and, if it has one, its key ID.
pub trait JwsKey {
    /// The one algorithm this key signs or verifies with.
    fn algorithm(&self) -> SignatureAlgorithm;
    /// The `kid` to put in or match against a header.
    fn key_id(&self) -> Option<&str> {
        None
    }
}

/// Signs JWS signing inputs. Implemented for every `signature::Signer<Signature>` that
/// is also a [`JwsKey`].
pub trait Signer: JwsKey {
    /// Signs `msg`.
    ///
    /// # Errors
    ///
    /// The key's or backend's error, e.g. a missing private key.
    fn try_sign(&self, msg: &[u8]) -> Result<Signature, Error>;
}

impl<T: signature::Signer<Signature> + JwsKey + ?Sized> Signer for T {
    fn try_sign(&self, msg: &[u8]) -> Result<Signature, Error> {
        signature::Signer::try_sign(self, msg).map_err(|e| signature_error(&e))
    }
}

/// Verifies JWS signatures. Implemented for every `signature::Verifier<Signature>` that
/// is also a [`JwsKey`].
pub trait Verifier: JwsKey {
    /// Verifies `sig` over `msg`.
    ///
    /// # Errors
    ///
    /// [`ErrorCode::VerificationFailed`](crate::ErrorCode::VerificationFailed) if it
    /// does not verify.
    fn verify(&self, msg: &[u8], sig: &Signature) -> Result<(), Error>;
}

impl<T: signature::Verifier<Signature> + JwsKey + ?Sized> Verifier for T {
    fn verify(&self, msg: &[u8], sig: &Signature) -> Result<(), Error> {
        signature::Verifier::verify(self, msg, sig).map_err(|e| signature_error(&e))
    }
}

/// Signs asynchronously; every [`Signer`] is one.
pub trait AsyncSigner: JwsKey {
    /// Signs `msg`.
    fn sign_async<'a>(&'a self, msg: &'a [u8]) -> BoxFuture<'a, Result<Signature, Error>>;
}

impl<T: Signer + ?Sized> AsyncSigner for T {
    fn sign_async<'a>(&'a self, msg: &'a [u8]) -> BoxFuture<'a, Result<Signature, Error>> {
        Box::pin(core::future::ready(self.try_sign(msg)))
    }
}

/// Verifies asynchronously; every [`Verifier`] is one.
pub trait AsyncVerifier: JwsKey {
    /// Verifies `sig` over `msg`.
    fn verify_async<'a>(
        &'a self,
        msg: &'a [u8],
        sig: &'a Signature,
    ) -> BoxFuture<'a, Result<(), Error>>;
}

impl<T: Verifier + ?Sized> AsyncVerifier for T {
    fn verify_async<'a>(
        &'a self,
        msg: &'a [u8],
        sig: &'a Signature,
    ) -> BoxFuture<'a, Result<(), Error>> {
        Box::pin(core::future::ready(self.verify(msg, sig)))
    }
}

/// The recipient's side of ECDH-ES: a private key that agrees on a shared secret with
/// a peer's public key, without handing out the private key.
pub trait KeyAgreement {
    /// The curve.
    fn curve(&self) -> Curve;
    /// The key ID, if it has one.
    fn key_id(&self) -> Option<&str> {
        None
    }
    /// The shared secret Z with the SEC1 public point `peer`.
    ///
    /// # Errors
    ///
    /// The backend's error, e.g. for a point not on the curve.
    fn agree(&self, peer: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error>;
}

/// [`KeyAgreement`] for keys that answer asynchronously; every [`KeyAgreement`] is one.
pub trait AsyncKeyAgreement {
    /// The curve.
    fn curve(&self) -> Curve;
    /// The key ID, if it has one.
    fn key_id(&self) -> Option<&str> {
        None
    }
    /// The shared secret Z with the SEC1 public point `peer`.
    fn agree_async<'a>(
        &'a self,
        peer: &'a [u8],
    ) -> BoxFuture<'a, Result<Zeroizing<Vec<u8>>, Error>>;
}

impl<T: KeyAgreement + ?Sized> AsyncKeyAgreement for T {
    fn curve(&self) -> Curve {
        KeyAgreement::curve(self)
    }
    fn key_id(&self) -> Option<&str> {
        KeyAgreement::key_id(self)
    }
    fn agree_async<'a>(
        &'a self,
        peer: &'a [u8],
    ) -> BoxFuture<'a, Result<Zeroizing<Vec<u8>>, Error>> {
        Box::pin(core::future::ready(self.agree(peer)))
    }
}

/// The jwz error a `signature::Error` carries, or a generic verification failure.
fn signature_error(e: &signature::Error) -> Error {
    use core::error::Error as _;
    e.source()
        .and_then(|source| source.downcast_ref::<Error>())
        .copied()
        .unwrap_or(Error::new(
            crate::ErrorCode::VerificationFailed,
            "signature",
        ))
}

/// A `signature::Error` carrying `e`, so a jwz error survives the trip through
/// RustCrypto's traits.
fn to_signature_error(e: Error) -> signature::Error {
    // `e` itself, not `Box::new(e)`: a boxed Error is an Error too, and would be
    // stored as a second box that `signature_error` cannot downcast.
    signature::Error::from_source(e)
}
