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

//! The operations of the HSM proxy interface, without a transport: what a transport
//! decodes from a request it hands to [`HsmProxy`], and what comes back it encodes. Every
//! call blocks on a session of the pool; a transport runs it where blocking is allowed.

use std::collections::HashMap;
use std::fmt;
use std::time::Duration;

use base64ct::{Base64UrlUnpadded, Encoding as _};
use const_oid::ObjectIdentifier;
use const_oid::db::rfc5912::{ID_EC_PUBLIC_KEY, SECP_256_R_1, SECP_384_R_1};
use cryptoki::error::RvError;
use der::asn1::BitString;
use der::{Any, Encode as _};
use pem_rfc7468::LineEnding;
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};

use crate::pkcs11::{
    Curve, Error, Iv, KeyEncryptionKey, MessageDigest, Sealed, SignInput, SigningKey,
};
use crate::pool::Pool;

/// What a key on the token is for. The interface names its keys by `key_id` only; which
/// kind a key is, the sidecar is told ([`KeySpec`]), never guessed from the name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeyKind {
    /// An ECDSA signing key on P-256.
    EcdsaP256,
    /// An ECDSA signing key on P-384.
    EcdsaP384,
    /// An AES-256 key-encryption key for AES-256-GCM.
    Aes256Gcm,
}

/// A key the sidecar serves: its `key_id`, which is the key's label on the token, and its
/// kind.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeySpec {
    /// The `key_id` of the interface and `CKA_LABEL` on the token.
    pub key_id: String,
    /// What the key is.
    pub kind: KeyKind,
}

/// How keys that are not on the token are treated at start.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MissingKeys {
    /// The start fails: a vendor's HSM is provisioned by its own tools.
    Refuse,
    /// The key is made on the token, sensitive, not extractable and for its one use: the
    /// simulator mode, in which a test needs no provisioning step.
    Make,
}

/// The hash the interface asks for before signing (`DigestAlgorithm`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Digest {
    /// `data` is the digest, of the curve's length.
    None,
    /// SHA-256 over `data`, applied by the token.
    Sha256,
    /// SHA-384 over `data`.
    Sha384,
    /// SHA-512 over `data`.
    Sha512,
}

/// A public key in the three forms `GetPublicKey` returns.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey {
    /// SubjectPublicKeyInfo, PEM.
    pub pem: String,
    /// SubjectPublicKeyInfo, DER.
    pub der: Vec<u8>,
    /// A JSON Web Key with `kty`, `crv`, `x` and `y` (RFC 7518 §6.2.1).
    pub jwk_json: String,
}

/// The certificate of a key, as `GetCertificate` returns it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Certificate {
    /// The end-entity certificate, PEM.
    pub pem: String,
    /// The chain from the end entity on, PEM; the token holds the end entity only, so
    /// that is all of it.
    pub chain_pem: Vec<String>,
}

/// What `HealthCheck` reports.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Health {
    /// Whether a session of the pool reached the token just now.
    pub serving: bool,
    /// The sidecar's version.
    pub version: &'static str,
    /// The module's description, as `C_GetInfo` gave it at start.
    pub hsm_info: String,
}

/// The kind of a refusal, which a transport maps to its own status.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum FailureKind {
    /// The request is not one the operation takes.
    InvalidArgument,
    /// No key, or no certificate, of that `key_id`.
    NotFound,
    /// The key exists but is not for this operation.
    FailedPrecondition,
    /// An algorithm the interface names that this sidecar does not offer.
    Unimplemented,
    /// No session came free in time, or the token does not answer.
    Unavailable,
    /// The token did something it should not.
    Internal,
}

/// A refused operation: its kind and a message that names the operation, the key and the
/// PKCS#11 return code, never data.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct Failure {
    /// The kind.
    pub kind: FailureKind,
    /// The message.
    pub message: String,
}

impl Failure {
    fn new(kind: FailureKind, message: impl Into<String>) -> Failure {
        Failure {
            kind,
            message: message.into(),
        }
    }

    fn from_token(e: &Error, decrypting: bool) -> Failure {
        let kind = match e {
            Error::Input(_) => FailureKind::InvalidArgument,
            Error::Busy(_) | Error::Module { .. } | Error::NoToken(_) => FailureKind::Unavailable,
            Error::KeyMismatch { .. } => FailureKind::FailedPrecondition,
            Error::Key {
                rv: Some(RvError::EncryptedDataInvalid | RvError::EncryptedDataLenRange),
                ..
            } if decrypting => FailureKind::InvalidArgument,
            _ => FailureKind::Internal,
        };
        Failure::new(kind, e.to_string())
    }
}

/// Why the sidecar did not start.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StartError {
    /// A key of the list is not on the token, and keys are not made.
    #[error("key {0} is not on the token")]
    Missing(String),
    /// Two entries of the list have one `key_id`.
    #[error("key {0} is listed twice")]
    Duplicate(String),
    /// The token refused.
    #[error(transparent)]
    Token(#[from] Error),
}

enum Key {
    Signing(SigningKey),
    Encryption(KeyEncryptionKey),
}

/// The HSM proxy's operations on a pool of sessions and the keys it was told to serve.
pub struct HsmProxy {
    pool: Pool,
    keys: HashMap<String, Key>,
    wait: Duration,
    iv: Iv,
    hsm_info: String,
}

impl fmt::Debug for HsmProxy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HsmProxy")
            .field("sessions", &self.pool.size())
            .field("keys", &self.keys.len())
            .field("hsm_info", &self.hsm_info)
            .finish_non_exhaustive()
    }
}

/// The longest input to sign or encrypt. The interface's operations take digests, short
/// messages and data-encryption keys; a larger request is refused before the token sees it.
pub const MAX_DATA_LEN: usize = 16 * 1024;

impl HsmProxy {
    /// Finds each key of `keys` on the token, or makes it when `missing` says so. `wait`
    /// bounds how long a call waits for a free session; `iv` is where an AES-GCM IV comes
    /// from, which differs between tokens; `hsm_info` is reported by [`HsmProxy::health`].
    ///
    /// # Errors
    ///
    /// [`StartError`] for a key that is missing or listed twice, or that the token refuses.
    pub fn start(
        pool: Pool,
        keys: &[KeySpec],
        missing: MissingKeys,
        wait: Duration,
        iv: Iv,
        hsm_info: String,
    ) -> Result<HsmProxy, StartError> {
        let mut found = HashMap::with_capacity(keys.len());
        for spec in keys {
            let id = spec.key_id.as_str();
            let key = pool.with(wait, |token| match (signing_curve(spec.kind), missing) {
                (Some(curve), MissingKeys::Make) => {
                    token.signing_key(id, curve).map(|k| Some(Key::Signing(k)))
                }
                (Some(curve), MissingKeys::Refuse) => token
                    .find_signing_key(id, curve)
                    .map(|k| k.map(Key::Signing)),
                (None, MissingKeys::Make) => token
                    .key_encryption_key(id)
                    .map(|k| Some(Key::Encryption(k))),
                (None, MissingKeys::Refuse) => token
                    .find_key_encryption_key(id)
                    .map(|k| k.map(Key::Encryption)),
            })?;
            let key = key.ok_or_else(|| StartError::Missing(spec.key_id.clone()))?;
            if found.insert(spec.key_id.clone(), key).is_some() {
                return Err(StartError::Duplicate(spec.key_id.clone()));
            }
        }
        Ok(HsmProxy {
            pool,
            keys: found,
            wait,
            iv,
            hsm_info,
        })
    }

    fn signing_key(&self, key_id: &str) -> Result<&SigningKey, Failure> {
        match self.keys.get(key_id) {
            Some(Key::Signing(key)) => Ok(key),
            Some(Key::Encryption(_)) => Err(Failure::new(
                FailureKind::FailedPrecondition,
                format!("key {key_id} is a key-encryption key, not a signing key"),
            )),
            None => Err(not_found(key_id)),
        }
    }

    fn encryption_key(&self, key_id: &str) -> Result<&KeyEncryptionKey, Failure> {
        match self.keys.get(key_id) {
            Some(Key::Encryption(key)) => Ok(key),
            Some(Key::Signing(_)) => Err(Failure::new(
                FailureKind::FailedPrecondition,
                format!("key {key_id} is a signing key, not a key-encryption key"),
            )),
            None => Err(not_found(key_id)),
        }
    }

    /// `Sign`: an ECDSA signature of `data` with `key_id`, as r and s of the curve's length
    /// (IEEE P1363). With [`Digest::None`], `data` is the digest and has the curve's length.
    ///
    /// # Errors
    ///
    /// [`Failure`] for an unknown key, a key-encryption key, input the token does not
    /// take, or a token that does not answer.
    pub fn sign(&self, key_id: &str, data: &[u8], digest: Digest) -> Result<Vec<u8>, Failure> {
        let key = self.signing_key(key_id)?;
        check_len(data)?;
        let input = match digest {
            Digest::None => SignInput::Digest(data),
            Digest::Sha256 => SignInput::Message(data, MessageDigest::Sha256),
            Digest::Sha384 => SignInput::Message(data, MessageDigest::Sha384),
            Digest::Sha512 => SignInput::Message(data, MessageDigest::Sha512),
        };
        self.pool
            .with(self.wait, |token| token.sign(key, input))
            .map_err(|e| Failure::from_token(&e, false))
    }

    /// `GetPublicKey`: the public key of the signing key `key_id`.
    ///
    /// # Errors
    ///
    /// [`Failure`] for an unknown key, a key-encryption key, or a token that does not
    /// answer.
    pub fn public_key(&self, key_id: &str) -> Result<PublicKey, Failure> {
        let key = self.signing_key(key_id)?;
        let point = self
            .pool
            .with(self.wait, |token| token.public_point(key))
            .map_err(|e| Failure::from_token(&e, false))?;
        encode_public_key(key, &point)
    }

    /// `Encrypt`: AES-256-GCM of `plaintext` under `key_id`, with `associated_data`
    /// authenticated.
    ///
    /// # Errors
    ///
    /// [`Failure`] for an unknown key, a signing key, a plaintext over [`MAX_DATA_LEN`], or
    /// a token that does not answer.
    pub fn encrypt(
        &self,
        key_id: &str,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<Sealed, Failure> {
        let key = self.encryption_key(key_id)?;
        check_len(plaintext)?;
        check_len(associated_data)?;
        self.pool
            .with(self.wait, |token| {
                token.encrypt(key, plaintext, associated_data, self.iv)
            })
            .map_err(|e| Failure::from_token(&e, false))
    }

    /// `Decrypt`: the plaintext of `sealed` under `key_id`, if it and `associated_data`
    /// authenticate.
    ///
    /// # Errors
    ///
    /// [`Failure`] with [`FailureKind::InvalidArgument`] for a ciphertext, IV, tag or
    /// associated data that do not authenticate; as [`HsmProxy::encrypt`] otherwise.
    pub fn decrypt(
        &self,
        key_id: &str,
        sealed: &Sealed,
        associated_data: &[u8],
    ) -> Result<Vec<u8>, Failure> {
        let key = self.encryption_key(key_id)?;
        check_len(&sealed.ciphertext)?;
        check_len(associated_data)?;
        self.pool
            .with(self.wait, |token| {
                token.decrypt(key, sealed, associated_data)
            })
            .map_err(|e| Failure::from_token(&e, true))
    }

    /// `GetCertificate`: the certificate the token keeps under `key_id`.
    ///
    /// # Errors
    ///
    /// [`Failure`] with [`FailureKind::NotFound`] for an unknown key or one without a
    /// certificate on the token.
    pub fn certificate(&self, key_id: &str) -> Result<Certificate, Failure> {
        self.signing_key(key_id)?;
        let der = self
            .pool
            .with(self.wait, |token| token.certificate(key_id))
            .map_err(|e| Failure::from_token(&e, false))?
            .ok_or_else(|| {
                Failure::new(
                    FailureKind::NotFound,
                    format!("the token holds no certificate for key {key_id}"),
                )
            })?;
        let pem = pem(&der, "CERTIFICATE")?;
        Ok(Certificate {
            chain_pem: vec![pem.clone()],
            pem,
        })
    }

    /// `HealthCheck`: whether a session reaches the token within the wait. Every session
    /// being busy counts as serving: the token is answering them, and a probe under load
    /// must not take the sidecar out of service.
    pub fn health(&self) -> Health {
        let serving = matches!(
            self.pool.with(self.wait, crate::pkcs11::Token::check),
            Ok(()) | Err(Error::Busy(_))
        );
        Health {
            serving,
            version: env!("CARGO_PKG_VERSION"),
            hsm_info: self.hsm_info.clone(),
        }
    }
}

/// The curve of a signing key; `None` for a key-encryption key.
fn signing_curve(kind: KeyKind) -> Option<Curve> {
    match kind {
        KeyKind::EcdsaP256 => Some(Curve::P256),
        KeyKind::EcdsaP384 => Some(Curve::P384),
        KeyKind::Aes256Gcm => None,
    }
}

fn not_found(key_id: &str) -> Failure {
    Failure::new(FailureKind::NotFound, format!("no key {key_id}"))
}

fn check_len(data: &[u8]) -> Result<(), Failure> {
    if data.len() > MAX_DATA_LEN {
        return Err(Failure::new(
            FailureKind::InvalidArgument,
            format!("an input is at most {MAX_DATA_LEN} bytes"),
        ));
    }
    Ok(())
}

fn internal(what: &str) -> Failure {
    Failure::new(FailureKind::Internal, what.to_owned())
}

fn pem(der: &[u8], label: &str) -> Result<String, Failure> {
    pem_rfc7468::encode_string(label, LineEnding::LF, der).map_err(|_| internal("PEM encoding"))
}

fn encode_public_key(key: &SigningKey, point: &[u8]) -> Result<PublicKey, Failure> {
    let (oid, crv): (ObjectIdentifier, &str) = match key.curve() {
        Curve::P256 => (SECP_256_R_1, "P-256"),
        Curve::P384 => (SECP_384_R_1, "P-384"),
        _ => return Err(internal("a curve the interface does not name")),
    };
    let field = key.curve().field_len();
    let (x, y) = match point {
        [0x04, rest @ ..] if rest.len() == 2 * field => rest.split_at(field),
        _ => return Err(internal("a public point of another form")),
    };
    let info = SubjectPublicKeyInfoOwned {
        algorithm: AlgorithmIdentifierOwned {
            oid: ID_EC_PUBLIC_KEY,
            parameters: Some(Any::encode_from(&oid).map_err(|_| internal("DER encoding"))?),
        },
        subject_public_key: BitString::from_bytes(point).map_err(|_| internal("DER encoding"))?,
    };
    let der = info.to_der().map_err(|_| internal("DER encoding"))?;
    Ok(PublicKey {
        pem: pem(&der, "PUBLIC KEY")?,
        der,
        jwk_json: format!(
            r#"{{"kty":"EC","crv":"{crv}","x":"{}","y":"{}"}}"#,
            Base64UrlUnpadded::encode_string(x),
            Base64UrlUnpadded::encode_string(y)
        ),
    })
}
