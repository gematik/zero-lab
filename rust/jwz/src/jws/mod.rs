//! JSON Web Signature (RFC 7515): compact serialization and, in [`json`], the JSON
//! serializations.
//!
//! Parsing runs the [`Policy`] on the header before any cryptography and yields a
//! `Jws<Unverified>`, which offers the header (to choose a key) but not the payload.
//! [`Jws::verify`] is the one place a JWS signature is checked; it yields a
//! `Jws<Verified>`, the only state with a payload accessor (ADR 0001, principle 4).
//!
//! ```
//! # #[cfg(feature = "crypto-rustcrypto")] {
//! use std::sync::Arc;
//! use jwz::crypto::rustcrypto::RustCrypto;
//! use jwz::header::HeaderParams;
//! use jwz::jwa::{Registry, SignatureAlgorithm};
//! use jwz::jws::{self, Jws};
//! use jwz::keys::SoftwareKey;
//! use jwz::profile::Profile;
//!
//! let registry = Registry::standard();
//! let backend = Arc::new(RustCrypto::new());
//! let key = SoftwareKey::generate(SignatureAlgorithm::ES256, &registry, backend)?;
//!
//! let token = jws::sign(b"hello", HeaderParams::new().typ("JWT"), &key)?;
//! let unverified = Jws::parse(&token, &Profile::strict().policy, &registry)?;
//! let verified = unverified.verify(&key)?;
//! assert_eq!(verified.payload(), b"hello");
//! # }
//! # Ok::<(), jwz::Error>(())
//! ```
//!
//! An unverified JWS has no payload accessor; this does not compile:
//!
//! ```compile_fail,E0599
//! fn leak(jws: jwz::jws::Jws<jwz::jws::Unverified>) -> Vec<u8> {
//!     jws.into_payload()
//! }
//! ```

pub mod json;

use alloc::string::String;
use alloc::vec::Vec;
use core::marker::PhantomData;

use crate::b64;
use crate::compact;
use crate::error::{Error, ErrorCode};
use crate::header::{Header, HeaderParams};
use crate::jwa::{Registry, SignatureAlgorithm};
use crate::keys::{AsyncSigner, AsyncVerifier, JwsKey, Signature, Signer, Verifier};
use crate::profile::Policy;

/// A JWS whose signature has not been checked: header only.
#[derive(Debug)]
pub enum Unverified {}
/// A JWS whose signature verified.
#[derive(Debug)]
pub enum Verified {}

/// A JSON Web Signature in state `S` ([`Unverified`] or [`Verified`]).
#[derive(Debug)]
pub struct Jws<S> {
    header: Header,
    alg: SignatureAlgorithm,
    /// The encoded protected header exactly as received: part of the signing input.
    protected: String,
    /// The encoded payload exactly as received: part of the signing input.
    encoded_payload: String,
    payload: Vec<u8>,
    signature: Signature,
    state: PhantomData<S>,
}

impl Jws<Unverified> {
    /// Parses a compact JWS and accepts its header under `policy`.
    ///
    /// # Errors
    ///
    /// [`ErrorCode::TokenTooLarge`] and [`ErrorCode::Malformed`] from the structure,
    /// [`ErrorCode::Base64`], [`ErrorCode::DuplicateMember`] and [`ErrorCode::Json`] from
    /// decoding, and the errors of [`Policy::check_jws`].
    pub fn parse(token: &str, policy: &Policy, registry: &Registry) -> Result<Self, Error> {
        // RFC 7515 §5.2 step 1: three parts; the size cap comes before any decoding.
        let [protected, encoded_payload, signature] =
            compact::split::<3>(token, policy.max_token_len)?;
        // RFC 7515 §5.2 steps 2-4: the header is a base64url JSON object.
        let header = Header::decode(protected)?;
        // RFC 7515 §5.2 step 5: the header is understood and acceptable.
        let alg = policy.check_jws(&header, registry)?;
        Ok(Jws {
            header,
            alg,
            protected: protected.into(),
            encoded_payload: encoded_payload.into(),
            // RFC 7515 §5.2 steps 6-7.
            payload: b64::decode(encoded_payload, "payload")?,
            signature: Signature::from(b64::decode(signature, "signature")?),
            state: PhantomData,
        })
    }

    pub(crate) fn from_parts(
        header: Header,
        alg: SignatureAlgorithm,
        protected: String,
        encoded_payload: String,
        payload: Vec<u8>,
        signature: Signature,
    ) -> Self {
        Jws {
            header,
            alg,
            protected,
            encoded_payload,
            payload,
            signature,
            state: PhantomData,
        }
    }

    /// Checks the signature with `key` (RFC 7515 §5.2 step 8).
    ///
    /// # Errors
    ///
    /// [`ErrorCode::KeyMismatch`] if `key` is for another algorithm or names another
    /// `kid` than the header; [`ErrorCode::VerificationFailed`] if the signature does not
    /// verify.
    pub fn verify(self, key: &dyn Verifier) -> Result<Jws<Verified>, Error> {
        self.check_key(key)?;
        key.verify(self.signing_input().as_bytes(), &self.signature)?;
        Ok(self.into_verified())
    }

    /// [`verify`](Self::verify) with a key that answers asynchronously.
    ///
    /// # Errors
    ///
    /// As [`verify`](Self::verify).
    pub async fn verify_async(self, key: &dyn AsyncVerifier) -> Result<Jws<Verified>, Error> {
        self.check_key(key)?;
        key.verify_async(self.signing_input().as_bytes(), &self.signature)
            .await?;
        Ok(self.into_verified())
    }

    /// The key must be for the header's algorithm (a key is bound to one; the header
    /// never chooses another for it) and, where both name one, the same `kid`.
    fn check_key(&self, key: &(impl JwsKey + ?Sized)) -> Result<(), Error> {
        if key.algorithm() != self.alg {
            return Err(Error::new(
                ErrorCode::KeyMismatch,
                "key for another algorithm",
            ));
        }
        if let (Some(expected), Some(actual)) = (self.header.kid(), key.key_id())
            && expected != actual
        {
            return Err(Error::new(ErrorCode::KeyMismatch, "kid"));
        }
        Ok(())
    }

    fn into_verified(self) -> Jws<Verified> {
        Jws {
            header: self.header,
            alg: self.alg,
            protected: self.protected,
            encoded_payload: self.encoded_payload,
            payload: self.payload,
            signature: self.signature,
            state: PhantomData,
        }
    }
}

impl<S> Jws<S> {
    /// The protected header, for choosing a key (`kid`, `x5c`, `jwk`).
    pub fn header(&self) -> &Header {
        &self.header
    }

    /// The algorithm the policy accepted.
    pub fn algorithm(&self) -> SignatureAlgorithm {
        self.alg
    }

    /// RFC 7515 §5.1 step 6 / §5.2 step 8: ASCII(protected || '.' || payload).
    fn signing_input(&self) -> String {
        signing_input(&self.protected, &self.encoded_payload)
    }
}

impl Jws<Verified> {
    /// The payload, available only after verification.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// The payload, consuming the JWS.
    pub fn into_payload(self) -> Vec<u8> {
        self.payload
    }
}

fn signing_input(protected: &str, encoded_payload: &str) -> String {
    let mut input = String::with_capacity(protected.len() + 1 + encoded_payload.len());
    input.push_str(protected);
    input.push('.');
    input.push_str(encoded_payload);
    input
}

/// The protected header for `key`: `params` plus `alg` and, unless set, `kid`.
fn protected_header(params: HeaderParams, key: &(impl JwsKey + ?Sized)) -> Result<String, Error> {
    let kid = key.key_id().filter(|_| !params.has("kid"));
    let mut set = alloc::vec![("alg", key.algorithm().as_str())];
    if let Some(kid) = kid {
        set.push(("kid", kid));
    }
    let members = params.into_members(&set);
    let json =
        serde_json::to_string(&members).map_err(|_| Error::new(ErrorCode::Json, "header"))?;
    Ok(b64::encode(json.as_bytes()))
}

/// Signs `payload` with `signer` into a compact JWS (RFC 7515 §5.1): `alg` from the
/// signer, `kid` from the signer unless `params` sets one.
///
/// # Errors
///
/// The signer's error, or [`ErrorCode::Json`] if the header cannot be serialized.
pub fn sign(payload: &[u8], params: HeaderParams, signer: &dyn Signer) -> Result<String, Error> {
    let protected = protected_header(params, signer)?;
    let encoded_payload = b64::encode(payload);
    let input = signing_input(&protected, &encoded_payload);
    let signature = signer.try_sign(input.as_bytes())?;
    Ok(compact_token(&input, &signature))
}

/// [`sign`] with a signer that answers asynchronously (an HSM, a KMS, WebCrypto).
///
/// # Errors
///
/// As [`sign`].
pub async fn sign_async(
    payload: &[u8],
    params: HeaderParams,
    signer: &dyn AsyncSigner,
) -> Result<String, Error> {
    let protected = protected_header(params, signer)?;
    let encoded_payload = b64::encode(payload);
    let input = signing_input(&protected, &encoded_payload);
    let signature = signer.sign_async(input.as_bytes()).await?;
    Ok(compact_token(&input, &signature))
}

fn compact_token(input: &str, signature: &Signature) -> String {
    let mut token = String::from(input);
    token.push('.');
    token.push_str(&b64::encode(signature.as_bytes()));
    token
}
