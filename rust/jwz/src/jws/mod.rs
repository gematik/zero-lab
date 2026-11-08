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
//! let profile = Profile::strict();
//! let params = HeaderParams::new().typ("JWT");
//! let token = jws::sign(b"hello", params, &key, &profile.policy, &registry)?;
//! let unverified = Jws::parse(&token, &profile.policy, &registry)?;
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
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::marker::PhantomData;

use crate::b64;
use crate::compact;
use crate::crypto::Backend;
use crate::error::{Error, ErrorCode};
use crate::header::{Header, HeaderParams};
use crate::jwa::{Registry, SignatureAlgorithm};
use crate::jwk::{AsyncKeyResolver, Jwk, KeyResolver};
use crate::keys::{AsyncSigner, AsyncVerifier, JwsKey, Signature, Signer, SoftwareKey, Verifier};
use crate::profile::{Policy, SigningKeyRule};

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
    /// What the verifying key must be under the policy the header was accepted by.
    key_rule: SigningKeyRule,
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
        let (alg, key_rule) = policy.accept_jws(&header, registry)?;
        Ok(Jws {
            header,
            alg,
            key_rule,
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
        (alg, key_rule): (SignatureAlgorithm, SigningKeyRule),
        protected: String,
        encoded_payload: String,
        payload: Vec<u8>,
        signature: Signature,
    ) -> Self {
        Jws {
            header,
            alg,
            key_rule,
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
    /// `kid` than the header; [`ErrorCode::PolicyViolation`] if it is on a curve the
    /// policy does not list ([`Policy::check_signing_key`]);
    /// [`ErrorCode::VerificationFailed`] if the signature does not verify.
    pub fn verify(self, key: &dyn Verifier) -> Result<Jws<Verified>, Error> {
        // RFC 8725 §3.3: the payload is reachable only through this check, so a token whose
        // signature fails is rejected whole.
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

    /// Checks the signature with the keys `resolver` offers for this header, each made a
    /// verifier for the accepted algorithm with `backend` and tried in turn; a key that
    /// does not fit the algorithm, or is on a curve the policy does not list, is passed
    /// over.
    ///
    /// # Errors
    ///
    /// The resolver's error; [`ErrorCode::VerificationFailed`] if no resolved key
    /// verifies the signature, none resolved included.
    pub fn verify_with<B: Backend>(
        self,
        resolver: &dyn KeyResolver,
        registry: &Registry,
        backend: &Arc<B>,
    ) -> Result<Jws<Verified>, Error> {
        let keys = resolver.resolve(&self.header, self.alg)?;
        self.verify_with_any(&keys, registry, backend)
    }

    /// [`verify_with`](Self::verify_with) with a resolver that answers asynchronously.
    ///
    /// # Errors
    ///
    /// As [`verify_with`](Self::verify_with).
    pub async fn verify_with_async<B: Backend>(
        self,
        resolver: &dyn AsyncKeyResolver,
        registry: &Registry,
        backend: &Arc<B>,
    ) -> Result<Jws<Verified>, Error> {
        let keys = resolver.resolve_async(&self.header, self.alg).await?;
        self.verify_with_any(&keys, registry, backend)
    }

    fn verify_with_any<B: Backend>(
        self,
        keys: &[Jwk],
        registry: &Registry,
        backend: &Arc<B>,
    ) -> Result<Jws<Verified>, Error> {
        let input = self.signing_input();
        let verifies = |jwk: &Jwk| {
            SoftwareKey::from_jwk(jwk, self.alg, registry, Arc::clone(backend)).is_ok_and(|key| {
                self.check_key(&key).is_ok()
                    && Verifier::verify(&key, input.as_bytes(), &self.signature).is_ok()
            })
        };
        if keys.iter().any(verifies) {
            Ok(self.into_verified())
        } else {
            Err(Error::new(
                ErrorCode::VerificationFailed,
                "no resolved key verifies the signature",
            ))
        }
    }

    /// The key must be for the header's algorithm (a key is bound to one; the header
    /// never chooses another for it), on a curve the policy lists and, where both name
    /// one, have the same `kid`.
    fn check_key(&self, key: &(impl JwsKey + ?Sized)) -> Result<(), Error> {
        // RFC 8725 §3.1: each key has one algorithm, checked here, when it is used.
        if key.algorithm() != self.alg {
            return Err(Error::new(
                ErrorCode::KeyMismatch,
                "key for another algorithm",
            ));
        }
        self.key_rule.check(key.curve())?;
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
            key_rule: self.key_rule,
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
fn protected_header(
    params: HeaderParams,
    key: &(impl JwsKey + ?Sized),
    policy: &Policy,
) -> Result<String, Error> {
    let kid = key.key_id().filter(|_| !params.has("kid"));
    let mut set = alloc::vec![("alg", key.algorithm().as_str())];
    if let Some(kid) = kid {
        set.push(("kid", kid));
    }
    let members = params.into_members(&set);
    policy.check_produced_jws(&Header::from_members(members.clone()))?;
    let json =
        serde_json::to_string(&members).map_err(|_| Error::new(ErrorCode::Json, "header"))?;
    Ok(b64::encode(json.as_bytes()))
}

/// Signs `payload` with `signer` into a compact JWS (RFC 7515 §5.1): `alg` from the
/// signer, `kid` from the signer unless `params` sets one. The signer's algorithm and
/// curve must be ones `policy` lists, so nothing is signed that the profile would
/// refuse to verify.
///
/// # Errors
///
/// The errors of [`Policy::check_signing_key`], and [`ErrorCode::PolicyViolation`] or
/// [`ErrorCode::Critical`] for a header the policy would refuse (`typ`, a required `kid`,
/// a key reference, `crit`), before anything is signed; the signer's error, or
/// [`ErrorCode::Json`] if the header cannot be serialized.
pub fn sign(
    payload: &[u8],
    params: HeaderParams,
    signer: &dyn Signer,
    policy: &Policy,
    registry: &Registry,
) -> Result<String, Error> {
    policy.check_signing_key(signer.algorithm(), signer.curve(), registry)?;
    let protected = protected_header(params, signer, policy)?;
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
    policy: &Policy,
    registry: &Registry,
) -> Result<String, Error> {
    policy.check_signing_key(signer.algorithm(), signer.curve(), registry)?;
    let protected = protected_header(params, signer, policy)?;
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
