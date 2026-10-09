//! JSON Web Encryption (RFC 7516): compact serialization and, in [`json`], the JSON
//! serializations; key management by ECDH-ES (direct and with AES Key Wrap), `dir` and
//! AES Key Wrap, content encryption by AES-GCM. CBC-HMAC, RSA, PBES2 and `zip` are
//! refused by [`Policy::check_jwe`].
//!
//! Parsing runs the [`Policy`] on the header and checks the structure (IV and tag
//! lengths, an empty encrypted key for the direct modes, a public `epk`) before any
//! cryptography, and yields a `Jwe<Encrypted>`, which offers the header (to choose a
//! key) but no plaintext. [`Jwe::decrypt`] yields a `Jwe<Decrypted>`, the only state with
//! a plaintext accessor (ADR 0001, principle 4).
//!
//! ```
//! # #[cfg(feature = "crypto-rustcrypto")] {
//! use std::sync::Arc;
//! use jwz::crypto::rustcrypto::RustCrypto;
//! use jwz::header::HeaderParams;
//! use jwz::jwa::{ContentEncryptionAlgorithm, Curve, KeyEncryptionAlgorithm, Registry};
//! use jwz::jwe::{self, DecryptionKey, EncryptionKey, Jwe};
//! use jwz::keys::SoftwareAgreementKey;
//! use jwz::profile::Profile;
//!
//! let registry = Registry::standard();
//! let backend = Arc::new(RustCrypto::new());
//! let recipient = SoftwareAgreementKey::generate(Curve::P256, backend.clone())?;
//!
//! let token = jwe::encrypt(
//!     b"hello",
//!     KeyEncryptionAlgorithm::ECDH_ES,
//!     ContentEncryptionAlgorithm::A256GCM,
//!     EncryptionKey::Public(&recipient.public_jwk()),
//!     HeaderParams::new(),
//!     &registry,
//!     backend.as_ref(),
//! )?;
//! let encrypted = Jwe::parse(&token, &Profile::strict().policy, &registry)?;
//! let decrypted = encrypted.decrypt(DecryptionKey::Agreement(&recipient), backend.as_ref())?;
//! assert_eq!(decrypted.plaintext(), b"hello");
//! # }
//! # Ok::<(), jwz::Error>(())
//! ```

pub mod ecdh;
pub mod json;

use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use core::marker::PhantomData;

use serde_json::{Map, Value};

use crate::b64;
use crate::compact;
use crate::crypto::{Backend, CryptoError, Zeroizing};
use crate::error::{Error, ErrorCode};
use crate::header::{Header, HeaderParams};
use crate::jwa::{
    ContentEncryptionAlgorithm, ContentEncryptionEntry, ContentEncryptionKind, Curve,
    HashAlgorithm, KeyEncryptionAlgorithm, KeyEncryptionEntry, KeyManagementMode, KeyType,
    Registry, Support,
};
use crate::jwk::{EcKey, Jwk, KeyMaterial};
use crate::keys::{AsyncKeyAgreement, KeyAgreement, SymmetricKey};
use crate::profile::Policy;

/// A JWE that has not been decrypted: header only.
#[derive(Debug)]
pub enum Encrypted {}
/// A JWE whose tag verified.
#[derive(Debug)]
pub enum Decrypted {}

/// The key a recipient decrypts with.
#[derive(Clone, Copy)]
pub enum DecryptionKey<'a> {
    /// For `ECDH-ES` and `ECDH-ES+A*KW`.
    Agreement(&'a dyn KeyAgreement),
    /// For `dir` and `A*KW`.
    Symmetric(&'a SymmetricKey),
}

/// The key a sender encrypts to.
#[derive(Clone, Copy, Debug)]
pub enum EncryptionKey<'a> {
    /// The recipient's public EC key, for `ECDH-ES` and `ECDH-ES+A*KW`.
    Public(&'a Jwk),
    /// The shared key, for `dir` and `A*KW`.
    Symmetric(&'a SymmetricKey),
}

/// The ECDH-ES inputs of a header, decoded at parse time.
#[derive(Clone, Debug)]
struct Agreement {
    curve: Curve,
    epk: Vec<u8>,
    apu: Vec<u8>,
    apv: Vec<u8>,
}

/// A JSON Web Encryption in state `S` ([`Encrypted`] or [`Decrypted`]).
pub struct Jwe<S> {
    header: Header,
    kek: KeyEncryptionEntry,
    cee: ContentEncryptionEntry,
    agreement: Option<Agreement>,
    /// The additional authenticated data: ASCII of the encoded protected header, and
    /// for the JSON serialization `'.'` and the encoded `aad` (RFC 7516 §5.1 step 14).
    aad: Vec<u8>,
    encrypted_key: Vec<u8>,
    iv: Vec<u8>,
    ciphertext: Vec<u8>,
    tag: Vec<u8>,
    plaintext: Zeroizing<Vec<u8>>,
    state: PhantomData<S>,
}

impl<S> core::fmt::Debug for Jwe<S> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Jwe")
            .field("alg", &self.kek.alg)
            .field("enc", &self.cee.enc)
            .finish_non_exhaustive()
    }
}

impl Jwe<Encrypted> {
    /// Parses a compact JWE and accepts its header under `policy`.
    ///
    /// # Errors
    ///
    /// [`ErrorCode::TokenTooLarge`] and [`ErrorCode::Malformed`] from the structure,
    /// [`ErrorCode::Base64`], [`ErrorCode::DuplicateMember`] and [`ErrorCode::Json`] from
    /// decoding, the errors of [`Policy::check_jwe`], [`ErrorCode::InvalidMember`] for an
    /// IV or tag of the wrong length or a malformed `epk`, `apu` or `apv`.
    pub fn parse(token: &str, policy: &Policy, registry: &Registry) -> Result<Self, Error> {
        // RFC 7516 §5.2 step 1: five parts; the size cap comes before any decoding.
        let [protected, encrypted_key, iv, ciphertext, tag] =
            compact::split::<5>(token, policy.max_token_len)?;
        // RFC 7516 §5.2 steps 2-4.
        let header = Header::decode(protected)?;
        Jwe::accept(
            header,
            protected.as_bytes().to_vec(),
            [encrypted_key, iv, ciphertext, tag],
            policy,
            registry,
        )
    }

    /// Everything after the header is decoded: the policy, then the structure.
    pub(crate) fn accept(
        header: Header,
        aad: Vec<u8>,
        [encrypted_key, iv, ciphertext, tag]: [&str; 4],
        policy: &Policy,
        registry: &Registry,
    ) -> Result<Self, Error> {
        // RFC 7516 §5.2 step 5: the header is understood and acceptable.
        let (kek, cee) = policy.check_jwe(&header, registry)?;
        let encrypted_key = b64::decode(encrypted_key, "encrypted key")?;
        let iv = b64::decode(iv, "iv")?;
        let ciphertext = b64::decode(ciphertext, "ciphertext")?;
        let tag = b64::decode(tag, "tag")?;
        // RFC 7518 §5.3: a 96-bit IV and a 128-bit tag; the registry holds the lengths.
        if iv.len() != cee.iv_len {
            return Err(Error::new(ErrorCode::InvalidMember, "iv length"));
        }
        if tag.len() != cee.tag_len {
            return Err(Error::new(ErrorCode::InvalidMember, "tag length"));
        }
        // RFC 7516 §5.2 step 10: the direct modes have an empty encrypted key.
        let direct = matches!(
            kek.mode,
            KeyManagementMode::DirectEncryption | KeyManagementMode::DirectKeyAgreement
        );
        if direct != encrypted_key.is_empty() {
            return Err(Error::new(ErrorCode::Malformed, "encrypted key"));
        }
        let agreement = if uses_agreement(kek.mode) {
            Some(agreement(&header, registry)?)
        } else {
            None
        };
        Ok(Jwe {
            header,
            kek,
            cee,
            agreement,
            aad,
            encrypted_key,
            iv,
            ciphertext,
            tag,
            plaintext: Zeroizing::new(Vec::new()),
            state: PhantomData,
        })
    }

    /// Determines the CEK with `key` and decrypts (RFC 7516 §5.2 steps 6-16).
    ///
    /// # Errors
    ///
    /// [`ErrorCode::KeyMismatch`] for a key of the wrong kind, curve, length, `alg` or
    /// `kid`; [`ErrorCode::VerificationFailed`] if the key unwrap or the tag fails;
    /// [`ErrorCode::UnsupportedAlgorithm`] if `backend` lacks a primitive.
    pub fn decrypt(
        self,
        key: DecryptionKey<'_>,
        backend: &dyn Backend,
    ) -> Result<Jwe<Decrypted>, Error> {
        let cek = match key {
            DecryptionKey::Symmetric(key) => self.symmetric_cek(key, backend)?,
            DecryptionKey::Agreement(key) => {
                let epk = self.check_agreement_key(key.curve(), key.key_id())?;
                let z = key.agree(epk)?;
                self.agreement_cek(&z, backend)?
            }
        };
        self.open(&cek, backend)
    }

    /// [`decrypt`](Self::decrypt) for ECDH-ES with a key that answers asynchronously.
    ///
    /// # Errors
    ///
    /// As [`decrypt`](Self::decrypt).
    pub async fn decrypt_async(
        self,
        key: &dyn AsyncKeyAgreement,
        backend: &dyn Backend,
    ) -> Result<Jwe<Decrypted>, Error> {
        let epk = self.check_agreement_key(key.curve(), key.key_id())?;
        let z = key.agree_async(epk).await?;
        let cek = self.agreement_cek(&z, backend)?;
        self.open(&cek, backend)
    }

    fn check_kid(&self, kid: Option<&str>) -> Result<(), Error> {
        match (self.header.kid(), kid) {
            (Some(expected), Some(actual)) if expected != actual => {
                Err(Error::new(ErrorCode::KeyMismatch, "kid"))
            }
            _ => Ok(()),
        }
    }

    /// The `epk` point, after checking the key is for this JWE.
    fn check_agreement_key(&self, curve: Curve, kid: Option<&str>) -> Result<&[u8], Error> {
        let agreement = self
            .agreement
            .as_ref()
            .ok_or(Error::new(ErrorCode::KeyMismatch, "key agreement key"))?;
        // RFC 7518 §4.6: the ephemeral key is on the recipient key's curve.
        if agreement.curve != curve {
            return Err(Error::new(ErrorCode::KeyMismatch, "epk curve"));
        }
        self.check_kid(kid)?;
        Ok(&agreement.epk)
    }

    fn symmetric_cek(
        &self,
        key: &SymmetricKey,
        backend: &dyn Backend,
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        check_symmetric_alg(key, self.kek.alg, self.cee.enc)?;
        self.check_kid(key.key_id())?;
        match self.kek.mode {
            // RFC 7518 §4.5: the shared key is the CEK.
            KeyManagementMode::DirectEncryption => {
                check_len(key.expose(), self.cee.key_len)?;
                Ok(Zeroizing::new(key.expose().to_vec()))
            }
            // RFC 7518 §4.4.
            KeyManagementMode::KeyWrapping { kek_len } => {
                check_len(key.expose(), kek_len)?;
                self.unwrap_cek(key.expose(), backend)
            }
            _ => Err(Error::new(ErrorCode::KeyMismatch, "symmetric key")),
        }
    }

    /// The CEK from the shared secret Z (RFC 7518 §4.6.2).
    fn agreement_cek(&self, z: &[u8], backend: &dyn Backend) -> Result<Zeroizing<Vec<u8>>, Error> {
        let agreement = self
            .agreement
            .as_ref()
            .ok_or(Error::new(ErrorCode::KeyMismatch, "key agreement key"))?;
        let sha256 = sha256(backend)?;
        match self.kek.mode {
            // RFC 7518 §4.6.2: AlgorithmID is `enc` for direct key agreement, `alg` with
            // key wrapping.
            KeyManagementMode::DirectKeyAgreement => ecdh::concat_kdf(
                sha256,
                z,
                self.cee.enc.as_str().as_bytes(),
                &agreement.apu,
                &agreement.apv,
                self.cee.key_len,
            ),
            KeyManagementMode::KeyAgreementWithKeyWrapping { kek_len } => {
                let kek = ecdh::concat_kdf(
                    sha256,
                    z,
                    self.kek.alg.as_str().as_bytes(),
                    &agreement.apu,
                    &agreement.apv,
                    kek_len,
                )?;
                self.unwrap_cek(&kek, backend)
            }
            _ => Err(Error::new(ErrorCode::KeyMismatch, "key agreement key")),
        }
    }

    fn unwrap_cek(&self, kek: &[u8], backend: &dyn Backend) -> Result<Zeroizing<Vec<u8>>, Error> {
        let wrap = backend.key_wrap(kek.len()).ok_or(UNSUPPORTED)?;
        let cek = wrap.unwrap(kek, &self.encrypted_key)?;
        // RFC 7516 §5.2 step 10: a CEK of the wrong length for `enc` is an error.
        if cek.len() != self.cee.key_len {
            return Err(Error::from(CryptoError::VerificationFailed));
        }
        Ok(cek)
    }

    /// RFC 7516 §5.2 steps 14-16: decrypt and authenticate.
    fn open(self, cek: &[u8], backend: &dyn Backend) -> Result<Jwe<Decrypted>, Error> {
        let aead = backend.aead(self.cee.enc).ok_or(UNSUPPORTED)?;
        let plaintext = aead.open(cek, &self.iv, &self.aad, &self.ciphertext, &self.tag)?;
        Ok(Jwe {
            header: self.header,
            kek: self.kek,
            cee: self.cee,
            agreement: self.agreement,
            aad: self.aad,
            encrypted_key: self.encrypted_key,
            iv: self.iv,
            ciphertext: self.ciphertext,
            tag: self.tag,
            plaintext,
            state: PhantomData,
        })
    }
}

impl<S> Jwe<S> {
    /// The header (protected and, in the JSON serialization, unprotected members), for
    /// choosing a key (`kid`, `epk`).
    pub fn header(&self) -> &Header {
        &self.header
    }

    /// The key management algorithm the policy accepted.
    pub fn algorithm(&self) -> KeyEncryptionAlgorithm {
        self.kek.alg
    }

    /// The content encryption algorithm the policy accepted.
    pub fn content_encryption(&self) -> ContentEncryptionAlgorithm {
        self.cee.enc
    }
}

impl Jwe<Decrypted> {
    /// The plaintext, available only after decryption.
    pub fn plaintext(&self) -> &[u8] {
        &self.plaintext
    }

    /// The plaintext, consuming the JWE.
    pub fn into_plaintext(self) -> Zeroizing<Vec<u8>> {
        self.plaintext
    }
}

const UNSUPPORTED: Error = Error::new(ErrorCode::UnsupportedAlgorithm, "crypto backend");

fn uses_agreement(mode: KeyManagementMode) -> bool {
    matches!(
        mode,
        KeyManagementMode::DirectKeyAgreement
            | KeyManagementMode::KeyAgreementWithKeyWrapping { .. }
    )
}

fn sha256(backend: &dyn Backend) -> Result<&dyn crate::crypto::Hash, Error> {
    backend.hash(HashAlgorithm::Sha256).ok_or(UNSUPPORTED)
}

fn check_len(key: &[u8], len: usize) -> Result<(), Error> {
    if key.len() == len {
        Ok(())
    } else {
        Err(Error::new(ErrorCode::KeyMismatch, "key length"))
    }
}

/// A symmetric key published with an `alg` is only for that `alg`; for `dir`, keys are
/// commonly published with the `enc` as their `alg` (RFC 7520 §5.6).
fn check_symmetric_alg(
    key: &SymmetricKey,
    alg: KeyEncryptionAlgorithm,
    enc: ContentEncryptionAlgorithm,
) -> Result<(), Error> {
    match key.algorithm() {
        None => Ok(()),
        Some(own) if own == alg.as_str() => Ok(()),
        Some(own) if alg == KeyEncryptionAlgorithm::DIR && own == enc.as_str() => Ok(()),
        Some(_) => Err(Error::new(
            ErrorCode::KeyMismatch,
            "key for another algorithm",
        )),
    }
}

/// `epk`, `apu` and `apv` of an ECDH-ES header (RFC 7518 §4.6.1).
fn agreement(header: &Header, registry: &Registry) -> Result<Agreement, Error> {
    let epk = header
        .epk()?
        .ok_or(Error::new(ErrorCode::MissingMember, "epk"))?;
    // RFC 7518 §4.6.1.1: epk is a public key; one with a private part is not an epk.
    if epk.is_private() {
        return Err(Error::new(ErrorCode::InvalidMember, "epk"));
    }
    epk.check(registry)?;
    let KeyMaterial::Ec(k) = &epk.material else {
        return Err(Error::new(ErrorCode::UnsupportedKeyType, "epk"));
    };
    let curve = registry
        .curve(&k.crv)
        .filter(|e| e.key_type == KeyType::EC && e.support == Support::Available)
        .map(|e| e.crv)
        .ok_or(Error::new(ErrorCode::UnknownCurve, "epk"))?;
    Ok(Agreement {
        curve,
        epk: k.point(),
        apu: party_info(header, "apu")?,
        apv: party_info(header, "apv")?,
    })
}

/// RFC 7518 §4.6.1.2-3: base64url, absent meaning empty.
fn party_info(header: &Header, name: &'static str) -> Result<Vec<u8>, Error> {
    match header.get(name) {
        None => Ok(Vec::new()),
        Some(Value::String(text)) => b64::decode(text, name),
        Some(_) => Err(Error::new(ErrorCode::InvalidMember, name)),
    }
}

/// What key management produced for one recipient.
struct Managed {
    cek: Zeroizing<Vec<u8>>,
    encrypted_key: Vec<u8>,
    /// Header members it sets: `epk`.
    members: Vec<(&'static str, Value)>,
}

/// The algorithm entries `alg` and `enc`, if available and implemented.
fn entries(
    alg: KeyEncryptionAlgorithm,
    enc: ContentEncryptionAlgorithm,
    registry: &Registry,
) -> Result<(KeyEncryptionEntry, ContentEncryptionEntry), Error> {
    let kek = registry
        .key_encryption(alg.as_str())
        .filter(|e| e.support == Support::Available)
        .ok_or(Error::new(ErrorCode::UnsupportedAlgorithm, "alg"))?;
    let cee = registry
        .content_encryption(enc.as_str())
        .filter(|e| e.support == Support::Available && e.kind == ContentEncryptionKind::Aead)
        .ok_or(Error::new(ErrorCode::UnsupportedAlgorithm, "enc"))?;
    Ok((*kek, *cee))
}

/// The sender's key management for one recipient (RFC 7516 §5.1 steps 1-5). `cek` is
/// the CEK shared by several recipients, which the direct modes cannot use.
fn manage(
    kek: &KeyEncryptionEntry,
    cee: &ContentEncryptionEntry,
    key: EncryptionKey<'_>,
    cek: Option<&[u8]>,
    party: (&[u8], &[u8]),
    registry: &Registry,
    backend: &dyn Backend,
) -> Result<Managed, Error> {
    let fresh_cek = || -> Result<Zeroizing<Vec<u8>>, Error> {
        match cek {
            Some(cek) => Ok(Zeroizing::new(cek.to_vec())),
            None => random(backend, cee.key_len),
        }
    };
    let shared_cek_refused = || {
        if cek.is_some() {
            Err(Error::new(
                ErrorCode::InvalidMember,
                "direct mode with several recipients",
            ))
        } else {
            Ok(())
        }
    };
    match (kek.mode, key) {
        (KeyManagementMode::DirectEncryption, EncryptionKey::Symmetric(key)) => {
            shared_cek_refused()?;
            check_symmetric_alg(key, kek.alg, cee.enc)?;
            check_len(key.expose(), cee.key_len)?;
            Ok(Managed {
                cek: Zeroizing::new(key.expose().to_vec()),
                encrypted_key: Vec::new(),
                members: Vec::new(),
            })
        }
        (KeyManagementMode::KeyWrapping { kek_len }, EncryptionKey::Symmetric(key)) => {
            check_symmetric_alg(key, kek.alg, cee.enc)?;
            check_len(key.expose(), kek_len)?;
            let cek = fresh_cek()?;
            let wrap = backend.key_wrap(kek_len).ok_or(UNSUPPORTED)?;
            let encrypted_key = wrap.wrap(key.expose(), &cek)?;
            Ok(Managed {
                cek,
                encrypted_key,
                members: Vec::new(),
            })
        }
        (mode, EncryptionKey::Public(jwk)) if uses_agreement(mode) => {
            let (curve, point) = recipient_point(jwk, kek.alg, registry)?;
            let (epk, z) = ecdh::sender(backend, curve, &point)?;
            let epk = Jwk::new(KeyMaterial::Ec(EcKey::from_point(curve.as_str(), &epk)));
            let epk = crate::json::parse_object(epk.to_json().as_bytes(), "epk")?;
            let members = vec![("epk", Value::Object(epk))];
            let (apu, apv) = party;
            let sha256 = sha256(backend)?;
            if let KeyManagementMode::KeyAgreementWithKeyWrapping { kek_len } = mode {
                let wrapping_key =
                    ecdh::concat_kdf(sha256, &z, kek.alg.as_str().as_bytes(), apu, apv, kek_len)?;
                let cek = fresh_cek()?;
                let wrap = backend.key_wrap(kek_len).ok_or(UNSUPPORTED)?;
                let encrypted_key = wrap.wrap(&wrapping_key, &cek)?;
                Ok(Managed {
                    cek,
                    encrypted_key,
                    members,
                })
            } else {
                shared_cek_refused()?;
                let cek = ecdh::concat_kdf(
                    sha256,
                    &z,
                    cee.enc.as_str().as_bytes(),
                    apu,
                    apv,
                    cee.key_len,
                )?;
                Ok(Managed {
                    cek,
                    encrypted_key: Vec::new(),
                    members,
                })
            }
        }
        _ => Err(Error::new(ErrorCode::KeyMismatch, "key for algorithm")),
    }
}

/// The recipient's curve and SEC1 point, after checking its JWK fits `alg`.
fn recipient_point(
    jwk: &Jwk,
    alg: KeyEncryptionAlgorithm,
    registry: &Registry,
) -> Result<(Curve, Vec<u8>), Error> {
    jwk.check(registry)?;
    let KeyMaterial::Ec(k) = &jwk.material else {
        return Err(Error::new(ErrorCode::KeyMismatch, "key agreement key"));
    };
    if jwk.alg.as_deref().is_some_and(|own| own != alg.as_str())
        || jwk.key_use.as_deref().is_some_and(|u| u != "enc")
    {
        return Err(Error::new(
            ErrorCode::KeyMismatch,
            "key for another algorithm",
        ));
    }
    let curve = registry
        .curve(&k.crv)
        .filter(|e| e.support == Support::Available)
        .map(|e| e.crv)
        .ok_or(Error::new(ErrorCode::UnknownCurve, "crv"))?;
    Ok((curve, k.point()))
}

fn random(backend: &dyn Backend, len: usize) -> Result<Zeroizing<Vec<u8>>, Error> {
    let mut bytes = Zeroizing::new(vec![0u8; len]);
    backend.rng().fill(&mut bytes)?;
    Ok(bytes)
}

/// The decoded `apu` and `apv` the producer set, for the KDF.
fn party_from(members: &Map<String, Value>) -> Result<(Vec<u8>, Vec<u8>), Error> {
    let header = Header::from_members(members.clone());
    Ok((party_info(&header, "apu")?, party_info(&header, "apv")?))
}

/// Encrypts `plaintext` into a compact JWE (RFC 7516 §5.1): `alg` and `enc` as given,
/// `kid` from the key unless `params` sets one, `apu`/`apv` from `params`.
///
/// # Errors
///
/// [`ErrorCode::UnsupportedAlgorithm`] for an algorithm not available or a primitive the
/// backend lacks; [`ErrorCode::KeyMismatch`] for a key that does not fit `alg`.
pub fn encrypt(
    plaintext: &[u8],
    alg: KeyEncryptionAlgorithm,
    enc: ContentEncryptionAlgorithm,
    key: EncryptionKey<'_>,
    params: HeaderParams,
    registry: &Registry,
    backend: &dyn Backend,
) -> Result<String, Error> {
    let (kek, cee) = entries(alg, enc, registry)?;
    let kid = key_id(key).filter(|_| !params.has("kid"));
    let mut set = vec![("alg", alg.as_str()), ("enc", enc.as_str())];
    if let Some(kid) = kid {
        set.push(("kid", kid));
    }
    let mut members = params.into_members(&set);
    let (apu, apv) = party_from(&members)?;
    let managed = manage(&kek, &cee, key, None, (&apu, &apv), registry, backend)?;
    for (name, value) in managed.members {
        members.insert(name.to_string(), value);
    }
    let protected = encode_header(&members)?;
    let iv = random(backend, cee.iv_len)?;
    let aead = backend.aead(enc).ok_or(UNSUPPORTED)?;
    // RFC 7516 §5.1 step 14: the AAD is ASCII(BASE64URL(UTF8(protected header))).
    let sealed = aead.seal(&managed.cek, &iv, protected.as_bytes(), plaintext)?;
    let mut token = protected;
    for part in [
        managed.encrypted_key.as_slice(),
        &iv,
        &sealed.ciphertext,
        &sealed.tag,
    ] {
        token.push('.');
        token.push_str(&b64::encode(part));
    }
    Ok(token)
}

fn key_id(key: EncryptionKey<'_>) -> Option<&str> {
    match key {
        EncryptionKey::Public(jwk) => jwk.kid.as_deref(),
        EncryptionKey::Symmetric(key) => key.key_id(),
    }
}

fn encode_header(members: &Map<String, Value>) -> Result<String, Error> {
    let json = serde_json::to_string(members).map_err(|_| Error::new(ErrorCode::Json, "header"))?;
    Ok(b64::encode(json.as_bytes()))
}
