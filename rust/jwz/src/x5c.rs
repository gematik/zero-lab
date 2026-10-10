//! Certificate chains in headers (`x5c`, RFC 7515 §4.1.6) and the `x5t#S256` binding
//! (RFC 7515 §4.1.8). jwz does not validate certificates: a [`ChainValidator`] does,
//! for whatever PKI the application trusts (ti-pki for the TI, WebPKI elsewhere).

use alloc::vec::Vec;

use crate::b64;
use crate::crypto::Hash;
use crate::crypto::asynchronous::BoxFuture;
use crate::error::{Error, ErrorCode};
use crate::header::Header;
use crate::jwk::Jwk;

/// Validates a certificate chain and returns the leaf's public key.
pub trait ChainValidator {
    /// Validates `chain` (DER, leaf first) and returns the leaf certificate's public key.
    ///
    /// # Errors
    ///
    /// The validator's reason for refusing the chain.
    fn validate(&self, chain: &[Vec<u8>]) -> Result<Jwk, Error>;
}

/// [`ChainValidator`] for validators that answer asynchronously (OCSP, a remote service).
pub trait AsyncChainValidator {
    /// See [`ChainValidator::validate`].
    fn validate_async<'a>(&'a self, chain: &'a [Vec<u8>]) -> BoxFuture<'a, Result<Jwk, Error>>;
}

/// The chain in `header`'s `x5c`, after checking `x5t#S256` against the leaf if both
/// are present.
///
/// # Errors
///
/// [`ErrorCode::MissingMember`] without `x5c`, the errors of [`Header::x5c`], and
/// [`ErrorCode::KeyMismatch`] if `x5t#S256` is not the leaf's SHA-256 thumbprint.
pub fn chain(header: &Header, sha256: &dyn Hash) -> Result<Vec<Vec<u8>>, Error> {
    let chain = header
        .x5c()?
        .ok_or(Error::new(ErrorCode::MissingMember, "x5c"))?;
    if let (Some(expected), Some(leaf)) = (header.x5t_s256(), chain.first()) {
        let expected = b64::decode(expected, "x5t#S256")?;
        // RFC 7515 §4.1.8: the base64url SHA-256 of the DER of the certificate. A
        // digest of public data: plain comparison, no constant time needed.
        if expected != sha256.digest(&[leaf]) {
            return Err(Error::new(ErrorCode::KeyMismatch, "x5t#S256"));
        }
    }
    Ok(chain)
}
