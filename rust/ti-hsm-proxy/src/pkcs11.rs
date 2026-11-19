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

use std::fmt::Write as _;
use std::path::Path;

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::error::{Error as Cryptoki, RvError};
use cryptoki::mechanism::aead::GcmParams;
use cryptoki::mechanism::{Mechanism, MechanismType};
use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle};
use cryptoki::session::{Session, SessionState, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;

/// Why an operation failed: what was done, with which key, and the PKCS#11 return code. It
/// holds no data, no PIN and no key material.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The module refused or failed an operation that concerns no key.
    #[error("{op}: {}", code(*.rv, .detail))]
    Module {
        /// What was done.
        op: &'static str,
        /// The PKCS#11 return code, if the module returned one.
        rv: Option<RvError>,
        /// What failed instead, when there is no return code (the module did not load).
        detail: String,
    },
    /// The module refused or failed an operation with a key.
    #[error("{op} with key {key}: {}", code(*.rv, .detail))]
    Key {
        /// What was done.
        op: &'static str,
        /// The key's label.
        key: String,
        /// The PKCS#11 return code, if the module returned one.
        rv: Option<RvError>,
        /// What failed instead, when there is no return code.
        detail: String,
    },
    /// No token has the label.
    #[error("no token labelled {0}")]
    NoToken(String),
    /// Every slot's token is initialised already, and none has the label to provision.
    #[error("no uninitialised token to provision as {0}")]
    NoFreeToken(String),
    /// The key exists, but is not what was asked for.
    #[error("key {key}: {reason}")]
    KeyMismatch {
        /// The key's label.
        key: String,
        /// What does not match.
        reason: &'static str,
    },
    /// The token returned something other than PKCS#11 says it returns.
    #[error("key {key}: the token returned {reason}")]
    Unexpected {
        /// The key's label.
        key: String,
        /// What was wrong with it.
        reason: &'static str,
    },
    /// The input is not one the operation takes; checked before the token sees it.
    #[error("{0}")]
    Input(&'static str),
    /// No session of the pool became free within the wait.
    #[error("no free session on the token within {0:?}")]
    Busy(std::time::Duration),
}

impl Error {
    /// Whether the session that met the error cannot be used again: the token closed it,
    /// went away, or logged the application out (a restart of a network HSM, a lost link).
    /// The pool replaces such a session ([`crate::Pool`]).
    #[must_use]
    pub fn session_lost(&self) -> bool {
        matches!(
            self.return_code(),
            Some(
                RvError::SessionHandleInvalid
                    | RvError::SessionClosed
                    | RvError::DeviceRemoved
                    | RvError::DeviceError
                    | RvError::TokenNotPresent
                    | RvError::TokenNotRecognized
                    | RvError::UserNotLoggedIn
                    | RvError::ObjectHandleInvalid
                    | RvError::KeyHandleInvalid
            )
        )
    }

    /// The PKCS#11 return code, if the module returned one.
    #[must_use]
    pub fn return_code(&self) -> Option<RvError> {
        match self {
            Error::Module { rv, .. } | Error::Key { rv, .. } => *rv,
            _ => None,
        }
    }
}

fn code(rv: Option<RvError>, detail: &str) -> String {
    match rv {
        Some(rv) => format!("PKCS#11 {rv:?}"),
        None => detail.to_owned(),
    }
}

fn split(e: &Cryptoki) -> (Option<RvError>, String) {
    match e {
        Cryptoki::Pkcs11(rv, _) => (Some(*rv), String::new()),
        other => (None, other.to_string()),
    }
}

fn module_error(op: &'static str) -> impl FnOnce(Cryptoki) -> Error {
    move |e| {
        let (rv, detail) = split(&e);
        Error::Module { op, rv, detail }
    }
}

fn key_error(op: &'static str, key: &str) -> impl FnOnce(Cryptoki) -> Error {
    let key = key.to_owned();
    move |e| {
        let (rv, detail) = split(&e);
        Error::Key {
            op,
            key,
            rv,
            detail,
        }
    }
}

/// The curves a signing key may be on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Curve {
    /// NIST P-256 (secp256r1).
    P256,
    /// NIST P-384 (secp384r1).
    P384,
    /// brainpoolP256r1 (RFC 5639), which the TI uses. The HSM proxy interface does not name
    /// it; it is here so that a token can be asked whether it has it.
    BrainpoolP256r1,
}

impl Curve {
    /// The curve's OID in DER, the value of `CKA_EC_PARAMS` (PKCS#11 3.1 §6.3.3, named
    /// curves only).
    fn params(self) -> &'static [u8] {
        match self {
            // 1.2.840.10045.3.1.7
            Curve::P256 => &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07],
            // 1.3.132.0.34
            Curve::P384 => &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22],
            // 1.3.36.3.3.2.8.1.1.7
            Curve::BrainpoolP256r1 => &[
                0x06, 0x09, 0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07,
            ],
        }
    }

    /// The length of a coordinate, and of r and of s in a signature, in bytes.
    #[must_use]
    pub fn field_len(self) -> usize {
        match self {
            Curve::P256 | Curve::BrainpoolP256r1 => 32,
            Curve::P384 => 48,
        }
    }

    fn from_params(params: &[u8]) -> Option<Curve> {
        [Curve::P256, Curve::P384, Curve::BrainpoolP256r1]
            .into_iter()
            .find(|c| c.params() == params)
    }
}

/// The hash a token applies before it signs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageDigest {
    /// SHA-256 (`CKM_ECDSA_SHA256`).
    Sha256,
    /// SHA-384 (`CKM_ECDSA_SHA384`).
    Sha384,
    /// SHA-512 (`CKM_ECDSA_SHA512`).
    Sha512,
}

/// What is signed.
#[derive(Clone, Copy, Debug)]
pub enum SignInput<'a> {
    /// A digest the caller made (`CKM_ECDSA`). Its length must be the curve's field length,
    /// as the HSM proxy interface requires.
    Digest(&'a [u8]),
    /// A message the token hashes with the digest before it signs.
    Message(&'a [u8], MessageDigest),
}

/// Where the 96-bit IV of an AES-GCM encryption comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Iv {
    /// From the token's random source (`C_GenerateRandom`), passed in with the call.
    Random,
    /// Made by the token during the encryption and written back, as a token in FIPS mode
    /// does. A token that does not would encrypt under the all-zero IV, so the result is
    /// refused when the IV comes back unchanged.
    FromToken,
    /// Given by the caller, for the conformance suite that compares output: an IV used twice
    /// with one key breaks GCM.
    #[cfg(feature = "conformance")]
    Given([u8; 12]),
}

/// An AES-GCM ciphertext with the IV it was made with and its 128-bit tag, as the HSM proxy
/// interface returns them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sealed {
    /// The IV.
    pub iv: Vec<u8>,
    /// The ciphertext, without the tag.
    pub ciphertext: Vec<u8>,
    /// The tag.
    pub tag: Vec<u8>,
}

/// A signing key pair on the token.
#[derive(Clone, Debug)]
pub struct SigningKey {
    label: String,
    curve: Curve,
    private: ObjectHandle,
    public: ObjectHandle,
}

impl SigningKey {
    /// The key's label.
    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }

    /// The key's curve.
    #[must_use]
    pub fn curve(&self) -> Curve {
        self.curve
    }
}

/// An AES-256 key-encryption key on the token.
#[derive(Clone, Debug)]
pub struct KeyEncryptionKey {
    label: String,
    handle: ObjectHandle,
}

impl KeyEncryptionKey {
    /// The key's label.
    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }
}

#[cfg(feature = "conformance")]
/// What a token says of a key: the attributes that make it a key that stays on the token
/// and has one use. `None` where the token does not report the attribute.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "one field per PKCS#11 attribute"
)]
pub struct KeyFacts {
    /// `CKA_SENSITIVE`
    pub sensitive: Option<bool>,
    /// `CKA_ALWAYS_SENSITIVE`
    pub always_sensitive: Option<bool>,
    /// `CKA_EXTRACTABLE`
    pub extractable: Option<bool>,
    /// `CKA_NEVER_EXTRACTABLE`
    pub never_extractable: Option<bool>,
    /// `CKA_SIGN`
    pub sign: Option<bool>,
    /// `CKA_ENCRYPT`
    pub encrypt: Option<bool>,
    /// `CKA_DECRYPT`
    pub decrypt: Option<bool>,
    /// `CKA_WRAP`
    pub wrap: Option<bool>,
    /// `CKA_UNWRAP`
    pub unwrap: Option<bool>,
    /// `CKA_DERIVE`
    pub derive: Option<bool>,
}

/// A loaded and initialised PKCS#11 module.
pub struct Module {
    pkcs11: Pkcs11,
}

impl Module {
    /// Loads the module at `path` and initialises it for use from several threads.
    ///
    /// # Errors
    ///
    /// [`Error::Module`] if it does not load or initialise.
    pub fn load(path: &Path) -> Result<Module, Error> {
        let pkcs11 = Pkcs11::new(path).map_err(module_error("load the module"))?;
        pkcs11
            .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
            .map_err(module_error("initialise the module"))?;
        Ok(Module { pkcs11 })
    }

    /// The module's description and version, as `C_GetInfo` reports them.
    ///
    /// # Errors
    ///
    /// [`Error::Module`] if the module does not answer.
    pub fn describe(&self) -> Result<String, Error> {
        let info = self
            .pkcs11
            .get_library_info()
            .map_err(module_error("read the module's information"))?;
        Ok(format!(
            "{} {} (PKCS#11 {})",
            info.library_description().trim(),
            info.library_version(),
            info.cryptoki_version()
        ))
    }

    /// Makes the token `label` with the security officer PIN `so_pin` and the user PIN
    /// `user_pin` on the first slot whose token is not initialised, unless a token has that
    /// label already. This is what a development or test token needs once; a vendor's HSM
    /// is provisioned by its own tools.
    ///
    /// # Errors
    ///
    /// [`Error::NoFreeToken`] if there is no uninitialised token, [`Error::Module`] if the
    /// module refuses.
    pub fn provision(
        &self,
        label: &str,
        so_pin: &AuthPin,
        user_pin: &AuthPin,
    ) -> Result<(), Error> {
        if self.slot(label).is_ok() {
            return Ok(());
        }
        let slots = self
            .pkcs11
            .get_slots_with_token()
            .map_err(module_error("list the slots"))?;
        let mut free = None;
        for slot in slots {
            let info = self
                .pkcs11
                .get_token_info(slot)
                .map_err(module_error("read a token's information"))?;
            if !info.token_initialized() {
                free = Some(slot);
                break;
            }
        }
        let slot = free.ok_or_else(|| Error::NoFreeToken(label.to_owned()))?;
        self.pkcs11
            .init_token(slot, so_pin, label)
            .map_err(module_error("initialise the token"))?;
        // A module may renumber its slots once a token is initialised (SoftHSM2 does).
        let slot = self.slot(label)?;
        let session = self
            .pkcs11
            .open_rw_session(slot)
            .map_err(module_error("open a session"))?;
        session
            .login(UserType::So, Some(so_pin))
            .map_err(module_error("log in as security officer"))?;
        session
            .init_pin(user_pin)
            .map_err(module_error("set the user PIN"))?;
        session
            .logout()
            .map_err(module_error("log out the security officer"))?;
        Ok(())
    }

    /// Opens a session on the token `label` and logs in as its user.
    ///
    /// # Errors
    ///
    /// [`Error::NoToken`] if no token has the label, [`Error::Module`] if the session or the
    /// login fails.
    pub fn open(&self, label: &str, user_pin: &AuthPin) -> Result<Token, Error> {
        let slot = self.slot(label)?;
        open_on(&self.pkcs11, slot, user_pin)
    }

    fn slot(&self, label: &str) -> Result<Slot, Error> {
        let slots = self
            .pkcs11
            .get_slots_with_initialized_token()
            .map_err(module_error("list the slots"))?;
        for slot in slots {
            let info = self
                .pkcs11
                .get_token_info(slot)
                .map_err(module_error("read a token's information"))?;
            if info.label().trim_end() == label {
                return Ok(slot);
            }
        }
        Err(Error::NoToken(label.to_owned()))
    }
}

/// A new session on `slot`, logged in as the user.
fn open_on(pkcs11: &Pkcs11, slot: Slot, user_pin: &AuthPin) -> Result<Token, Error> {
    let session = pkcs11
        .open_rw_session(slot)
        .map_err(module_error("open a session"))?;
    // The login state is the application's, not the session's: another session may have
    // logged in already.
    match session.login(UserType::User, Some(user_pin)) {
        Ok(()) | Err(Cryptoki::Pkcs11(RvError::UserAlreadyLoggedIn, _)) => {}
        Err(e) => return Err(module_error("log in")(e)),
    }
    Ok(Token {
        pkcs11: pkcs11.clone(),
        slot,
        session,
    })
}

/// A logged-in session on one token. A session is used by one thread at a time; a server
/// opens one per worker.
pub struct Token {
    pkcs11: Pkcs11,
    slot: Slot,
    session: Session,
}

fn mismatch(label: &str, reason: &'static str) -> Error {
    Error::KeyMismatch {
        key: label.to_owned(),
        reason,
    }
}

/// A key found on the token is served only if the token says it cannot leave: sensitive and
/// not extractable. One a vendor's tool made otherwise is refused, not used.
fn stays_on_the_token(held: &[Attribute], label: &str) -> Result<(), Error> {
    if held.contains(&Attribute::Sensitive(true)) && held.contains(&Attribute::Extractable(false)) {
        Ok(())
    } else {
        Err(mismatch(
            label,
            "the token does not keep it sensitive and not extractable",
        ))
    }
}

/// The longest label a key may have. The HSM proxy interface's `key_id` becomes `CKA_LABEL`.
const MAX_LABEL_LEN: usize = 64;

fn check_label(label: &str) -> Result<(), Error> {
    if label.is_empty()
        || label.len() > MAX_LABEL_LEN
        || !label.bytes().all(|b| b.is_ascii_graphic())
    {
        return Err(Error::Input(
            "a key label is 1 to 64 visible ASCII characters",
        ));
    }
    Ok(())
}

const GCM_IV_LEN: usize = 12;
const GCM_IV_LEN_U32: u32 = 12;
const GCM_TAG_LEN: usize = 16;
/// The tag length in bits, as `CK_GCM_PARAMS` takes it.
const GCM_TAG_BITS: u64 = 128;

impl Token {
    /// A new session on the same token, logged in as the user: what replaces a session that
    /// was lost ([`Error::session_lost`]).
    ///
    /// # Errors
    ///
    /// [`Error::Module`] if the session or the login fails, as while the token is away.
    pub fn reopen(&self, user_pin: &AuthPin) -> Result<Token, Error> {
        open_on(&self.pkcs11, self.slot, user_pin)
    }

    /// Makes, under `label`, what a careless provisioning tool would: an AES key of 128 bits,
    /// extractable and not sensitive. The sidecar must refuse to serve it.
    ///
    /// # Errors
    ///
    /// [`Error::Key`] if the token refuses.
    #[cfg(feature = "conformance")]
    pub fn make_unfit_secret_key(&self, label: &str) -> Result<(), Error> {
        let id = label.as_bytes().to_vec();
        self.session
            .generate_key(
                &Mechanism::AesKeyGen,
                &[
                    Attribute::Class(ObjectClass::SECRET_KEY),
                    Attribute::KeyType(KeyType::AES),
                    Attribute::ValueLen(16.into()),
                    Attribute::Token(true),
                    Attribute::Private(true),
                    Attribute::Sensitive(false),
                    Attribute::Extractable(true),
                    Attribute::Encrypt(true),
                    Attribute::Decrypt(true),
                    Attribute::Label(id.clone()),
                    Attribute::Id(id),
                ],
            )
            .map(drop)
            .map_err(key_error("make an unfit key", label))
    }

    /// Makes, under `label`, an EC key pair whose private key is extractable. The sidecar must
    /// refuse to serve it.
    ///
    /// # Errors
    ///
    /// [`Error::Key`] if the token refuses.
    #[cfg(feature = "conformance")]
    pub fn make_unfit_signing_key(&self, label: &str, curve: Curve) -> Result<(), Error> {
        let id = label.as_bytes().to_vec();
        self.session
            .generate_key_pair(
                &Mechanism::EccKeyPairGen,
                &[
                    Attribute::Token(true),
                    Attribute::Verify(true),
                    Attribute::EcParams(curve.params().to_vec()),
                    Attribute::Label(id.clone()),
                    Attribute::Id(id.clone()),
                ],
                &[
                    Attribute::Token(true),
                    Attribute::Private(true),
                    Attribute::Sensitive(false),
                    Attribute::Extractable(true),
                    Attribute::Sign(true),
                    Attribute::Label(id.clone()),
                    Attribute::Id(id),
                ],
            )
            .map(drop)
            .map_err(key_error("make an unfit key", label))
    }

    /// Logs the application out of the token, which ends the login of every session: what
    /// a token that restarts does to a client.
    ///
    /// # Errors
    ///
    /// [`Error::Module`] if the token refuses.
    #[cfg(feature = "conformance")]
    pub fn log_out(&self) -> Result<(), Error> {
        self.session.logout().map_err(module_error("log out"))
    }

    /// The mechanisms the token's slot lists, by their PKCS#11 names.
    ///
    /// # Errors
    ///
    /// [`Error::Module`] if the module does not answer.
    pub fn mechanisms(&self) -> Result<Vec<String>, Error> {
        let list = self
            .pkcs11
            .get_mechanism_list(self.slot)
            .map_err(module_error("list the mechanisms"))?;
        Ok(list.iter().map(ToString::to_string).collect())
    }

    /// Whether the token lists `mechanism`.
    ///
    /// # Errors
    ///
    /// [`Error::Module`] if the module does not answer.
    pub fn has_mechanism(&self, mechanism: MechanismType) -> Result<bool, Error> {
        Ok(self
            .pkcs11
            .get_mechanism_list(self.slot)
            .map_err(module_error("list the mechanisms"))?
            .contains(&mechanism))
    }

    fn find(&self, class: ObjectClass, label: &str) -> Result<Option<ObjectHandle>, Error> {
        let found = self
            .session
            .find_objects(&[
                Attribute::Class(class),
                Attribute::Label(label.as_bytes().to_vec()),
            ])
            .map_err(key_error("find the key", label))?;
        match found.as_slice() {
            [] => Ok(None),
            [one] => Ok(Some(*one)),
            _ => Err(Error::KeyMismatch {
                key: label.to_owned(),
                reason: "more than one key has the label",
            }),
        }
    }

    /// The signing key `label` on `curve`: the one on the token, or a new one made there.
    /// A new private key is sensitive, not extractable and only signs; its public key only
    /// verifies.
    ///
    /// # Errors
    ///
    /// [`Error::Input`] for a label outside its grammar; [`Error::KeyMismatch`] for a key of
    /// that label on another curve, or without its public key; [`Error::Key`] if the token
    /// refuses.
    pub fn signing_key(&self, label: &str, curve: Curve) -> Result<SigningKey, Error> {
        if let Some(key) = self.find_signing_key(label, curve)? {
            return Ok(key);
        }
        let id = label.as_bytes().to_vec();
        let public_template = [
            Attribute::Token(true),
            Attribute::Private(false),
            Attribute::Verify(true),
            Attribute::Encrypt(false),
            Attribute::Wrap(false),
            Attribute::Derive(false),
            Attribute::EcParams(curve.params().to_vec()),
            Attribute::Label(id.clone()),
            Attribute::Id(id.clone()),
        ];
        let private_template = [
            Attribute::Token(true),
            Attribute::Private(true),
            Attribute::Sensitive(true),
            Attribute::Extractable(false),
            Attribute::Sign(true),
            Attribute::Decrypt(false),
            Attribute::Unwrap(false),
            Attribute::Derive(false),
            Attribute::Label(id.clone()),
            Attribute::Id(id),
        ];
        let (public, private) = self
            .session
            .generate_key_pair(
                &Mechanism::EccKeyPairGen,
                &public_template,
                &private_template,
            )
            .map_err(key_error("make the signing key", label))?;
        Ok(SigningKey {
            label: label.to_owned(),
            curve,
            private,
            public,
        })
    }

    /// The signing key `label` on `curve` if the token has it; nothing is made.
    ///
    /// # Errors
    ///
    /// As [`Token::signing_key`].
    pub fn find_signing_key(&self, label: &str, curve: Curve) -> Result<Option<SigningKey>, Error> {
        check_label(label)?;
        let Some(private) = self.find(ObjectClass::PRIVATE_KEY, label)? else {
            return Ok(None);
        };
        let public =
            self.find(ObjectClass::PUBLIC_KEY, label)?
                .ok_or_else(|| Error::KeyMismatch {
                    key: label.to_owned(),
                    reason: "it has no public key",
                })?;
        let params = self.attribute_bytes(public, AttributeType::EcParams, label)?;
        if Curve::from_params(&params) != Some(curve) {
            return Err(mismatch(label, "it is on another curve"));
        }
        let held = self.held(
            private,
            label,
            &[
                AttributeType::KeyType,
                AttributeType::Sign,
                AttributeType::Sensitive,
                AttributeType::Extractable,
                AttributeType::Id,
                AttributeType::EcParams,
            ],
        )?;
        if !held.contains(&Attribute::KeyType(KeyType::EC)) {
            return Err(mismatch(label, "its private key is not an EC key"));
        }
        if !held.contains(&Attribute::Sign(true)) {
            return Err(mismatch(label, "its private key does not sign"));
        }
        stays_on_the_token(&held, label)?;
        // The private key belongs to the public one GetPublicKey answers with: the same curve,
        // and the same CKA_ID where the token keeps one.
        let public_id = self.held(public, label, &[AttributeType::Id])?;
        for attribute in &held {
            let agrees = match attribute {
                Attribute::EcParams(own) => own == &params,
                Attribute::Id(own) => public_id.iter().all(|a| match a {
                    Attribute::Id(other) => own == other,
                    _ => true,
                }),
                _ => true,
            };
            if !agrees {
                return Err(mismatch(
                    label,
                    "its private key is not the one of its public key",
                ));
            }
        }
        Ok(Some(SigningKey {
            label: label.to_owned(),
            curve,
            private,
            public,
        }))
    }

    /// The AES-256 key-encryption key `label`: the one on the token, or a new one made
    /// there. A new key is sensitive, not extractable, encrypts and decrypts, and does
    /// nothing else.
    ///
    /// # Errors
    ///
    /// [`Error::Input`] for a label outside its grammar; [`Error::Key`] if the token refuses.
    pub fn key_encryption_key(&self, label: &str) -> Result<KeyEncryptionKey, Error> {
        if let Some(key) = self.find_key_encryption_key(label)? {
            return Ok(key);
        }
        let id = label.as_bytes().to_vec();
        let template = [
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::KeyType(KeyType::AES),
            Attribute::ValueLen(32.into()),
            Attribute::Token(true),
            Attribute::Private(true),
            Attribute::Sensitive(true),
            Attribute::Extractable(false),
            Attribute::Encrypt(true),
            Attribute::Decrypt(true),
            Attribute::Wrap(false),
            Attribute::Unwrap(false),
            Attribute::Sign(false),
            Attribute::Verify(false),
            Attribute::Derive(false),
            Attribute::Label(id.clone()),
            Attribute::Id(id),
        ];
        let handle = self
            .session
            .generate_key(&Mechanism::AesKeyGen, &template)
            .map_err(key_error("make the key-encryption key", label))?;
        Ok(KeyEncryptionKey {
            label: label.to_owned(),
            handle,
        })
    }

    /// The key-encryption key `label` if the token has it; nothing is made.
    ///
    /// # Errors
    ///
    /// As [`Token::key_encryption_key`].
    pub fn find_key_encryption_key(&self, label: &str) -> Result<Option<KeyEncryptionKey>, Error> {
        check_label(label)?;
        let Some(handle) = self.find(ObjectClass::SECRET_KEY, label)? else {
            return Ok(None);
        };
        let held = self.held(
            handle,
            label,
            &[
                AttributeType::KeyType,
                AttributeType::ValueLen,
                AttributeType::Encrypt,
                AttributeType::Decrypt,
                AttributeType::Sensitive,
                AttributeType::Extractable,
            ],
        )?;
        if !held.contains(&Attribute::KeyType(KeyType::AES))
            || !held.contains(&Attribute::ValueLen(32.into()))
        {
            return Err(mismatch(label, "it is not an AES-256 key"));
        }
        if !held.contains(&Attribute::Encrypt(true)) || !held.contains(&Attribute::Decrypt(true)) {
            return Err(mismatch(label, "it does not encrypt and decrypt"));
        }
        stays_on_the_token(&held, label)?;
        Ok(Some(KeyEncryptionKey {
            label: label.to_owned(),
            handle,
        }))
    }

    /// The attributes of `handle` among `types` that the token reports.
    fn held(
        &self,
        handle: ObjectHandle,
        label: &str,
        types: &[AttributeType],
    ) -> Result<Vec<Attribute>, Error> {
        self.session
            .get_attributes(handle, types)
            .map_err(key_error("read the key's attributes", label))
    }

    /// The DER of the certificate object labelled `label`, if the token holds one. A token
    /// keeps a key's certificate under the key's label.
    ///
    /// # Errors
    ///
    /// [`Error::Input`] for a label outside its grammar; [`Error::KeyMismatch`] for more than
    /// one certificate of that label; [`Error::Key`] if the token refuses.
    pub fn certificate(&self, label: &str) -> Result<Option<Vec<u8>>, Error> {
        check_label(label)?;
        match self.find(ObjectClass::CERTIFICATE, label)? {
            Some(handle) => self
                .attribute_bytes(handle, AttributeType::Value, label)
                .map(Some),
            None => Ok(None),
        }
    }

    /// Whether the session still answers and is logged in as the user: the cheapest call
    /// that reaches the token.
    ///
    /// # Errors
    ///
    /// [`Error::Module`] if the module or the token does not answer, with
    /// `CKR_USER_NOT_LOGGED_IN` if the token logged the application out.
    pub fn check(&self) -> Result<(), Error> {
        let info = self
            .session
            .get_session_info()
            .map_err(module_error("read the session's state"))?;
        match info.session_state() {
            SessionState::RwUser => Ok(()),
            _ => Err(Error::Module {
                op: "read the session's state",
                rv: Some(RvError::UserNotLoggedIn),
                detail: String::new(),
            }),
        }
    }

    /// The public key of `key` as an uncompressed SEC1 point, whether the token returns
    /// `CKA_EC_POINT` as the point or, as PKCS#11 specifies, DER-wrapped in an OCTET STRING.
    ///
    /// # Errors
    ///
    /// [`Error::Key`] if the token refuses, [`Error::Unexpected`] for a point of another
    /// form or length.
    pub fn public_point(&self, key: &SigningKey) -> Result<Vec<u8>, Error> {
        let raw = self.attribute_bytes(key.public, AttributeType::EcPoint, &key.label)?;
        let len = 1 + 2 * key.curve.field_len();
        let point = match raw.as_slice() {
            [0x04, rest @ ..] if raw.len() == len && rest.len() == len - 1 => raw.clone(),
            [0x04, n, rest @ ..] if usize::from(*n) == rest.len() && rest.len() == len => {
                rest.to_vec()
            }
            [0x04, 0x81, n, rest @ ..] if usize::from(*n) == rest.len() && rest.len() == len => {
                rest.to_vec()
            }
            _ => {
                return Err(Error::Unexpected {
                    key: key.label.clone(),
                    reason: "a public point of another form or length",
                });
            }
        };
        if point.first() != Some(&0x04) {
            return Err(Error::Unexpected {
                key: key.label.clone(),
                reason: "a compressed public point",
            });
        }
        Ok(point)
    }

    #[cfg(feature = "conformance")]
    /// Whether the token returns `CKA_EC_POINT` DER-wrapped, as PKCS#11 specifies, rather
    /// than as the bare point.
    ///
    /// # Errors
    ///
    /// [`Error::Key`] if the token refuses.
    pub fn ec_point_is_wrapped(&self, key: &SigningKey) -> Result<bool, Error> {
        let raw = self.attribute_bytes(key.public, AttributeType::EcPoint, &key.label)?;
        Ok(raw.len() != 1 + 2 * key.curve.field_len())
    }

    /// Signs `input` with `key` and returns the signature as r and s, each of the curve's
    /// field length (IEEE P1363), as the HSM proxy interface returns it.
    ///
    /// # Errors
    ///
    /// [`Error::Input`] for a digest of another length than the curve's; [`Error::Key`] if
    /// the token refuses; [`Error::Unexpected`] for a signature of another length.
    pub fn sign(&self, key: &SigningKey, input: SignInput<'_>) -> Result<Vec<u8>, Error> {
        let (mechanism, data) = match input {
            SignInput::Digest(digest) => {
                if digest.len() != key.curve.field_len() {
                    return Err(Error::Input("a digest has the length of the key's curve"));
                }
                (Mechanism::Ecdsa, digest)
            }
            SignInput::Message(message, MessageDigest::Sha256) => (Mechanism::EcdsaSha256, message),
            SignInput::Message(message, MessageDigest::Sha384) => (Mechanism::EcdsaSha384, message),
            SignInput::Message(message, MessageDigest::Sha512) => (Mechanism::EcdsaSha512, message),
        };
        let signature = self
            .session
            .sign(&mechanism, key.private, data)
            .map_err(key_error("sign", &key.label))?;
        if signature.len() != 2 * key.curve.field_len() {
            return Err(Error::Unexpected {
                key: key.label.clone(),
                reason: "a signature of another length than r and s of the curve",
            });
        }
        Ok(signature)
    }

    /// Encrypts `plaintext` with `key` in AES-256-GCM, with `associated_data` authenticated
    /// and a 96-bit IV from `iv`.
    ///
    /// # Errors
    ///
    /// [`Error::Key`] if the token refuses; [`Error::Unexpected`] if the token was to make
    /// the IV and did not, or for an output shorter than a tag.
    pub fn encrypt(
        &self,
        key: &KeyEncryptionKey,
        plaintext: &[u8],
        associated_data: &[u8],
        iv: Iv,
    ) -> Result<Sealed, Error> {
        let mut iv_buffer = match iv {
            Iv::Random => self
                .session
                .generate_random_vec(GCM_IV_LEN_U32)
                .map_err(key_error("make an IV", &key.label))?,
            Iv::FromToken => vec![0; GCM_IV_LEN],
            #[cfg(feature = "conformance")]
            Iv::Given(given) => given.to_vec(),
        };
        let sealed = {
            let params = GcmParams::new(&mut iv_buffer, associated_data, GCM_TAG_BITS.into())
                .map_err(key_error("set the GCM parameters", &key.label))?;
            self.session
                .encrypt(&Mechanism::AesGcm(params), key.handle, plaintext)
                .map_err(key_error("encrypt", &key.label))?
        };
        if matches!(iv, Iv::FromToken) && iv_buffer.iter().all(|&b| b == 0) {
            return Err(Error::Unexpected {
                key: key.label.clone(),
                reason: "no IV: it encrypted under the all-zero IV it was given",
            });
        }
        let Some(split_at) = sealed.len().checked_sub(GCM_TAG_LEN) else {
            return Err(Error::Unexpected {
                key: key.label.clone(),
                reason: "a ciphertext shorter than its tag",
            });
        };
        let (ciphertext, tag) = sealed.split_at(split_at);
        Ok(Sealed {
            iv: iv_buffer,
            ciphertext: ciphertext.to_vec(),
            tag: tag.to_vec(),
        })
    }

    /// Decrypts `sealed` with `key`, authenticating `associated_data`.
    ///
    /// # Errors
    ///
    /// [`Error::Input`] for an IV or tag of another length; [`Error::Key`] if the token
    /// refuses, a tag that does not verify among it.
    pub fn decrypt(
        &self,
        key: &KeyEncryptionKey,
        sealed: &Sealed,
        associated_data: &[u8],
    ) -> Result<Vec<u8>, Error> {
        if sealed.iv.len() != GCM_IV_LEN || sealed.tag.len() != GCM_TAG_LEN {
            return Err(Error::Input("the IV is 12 bytes and the tag 16"));
        }
        let mut iv = sealed.iv.clone();
        let mut input = Vec::with_capacity(sealed.ciphertext.len() + GCM_TAG_LEN);
        input.extend_from_slice(&sealed.ciphertext);
        input.extend_from_slice(&sealed.tag);
        let params = GcmParams::new(&mut iv, associated_data, GCM_TAG_BITS.into())
            .map_err(key_error("set the GCM parameters", &key.label))?;
        self.session
            .decrypt(&Mechanism::AesGcm(params), key.handle, &input)
            .map_err(key_error("decrypt", &key.label))
    }

    #[cfg(feature = "conformance")]
    /// What the token says of the private key of `key`.
    ///
    /// # Errors
    ///
    /// [`Error::Key`] if the token refuses.
    pub fn signing_key_facts(&self, key: &SigningKey) -> Result<KeyFacts, Error> {
        self.facts(key.private, &key.label)
    }

    #[cfg(feature = "conformance")]
    /// What the token says of `key`.
    ///
    /// # Errors
    ///
    /// [`Error::Key`] if the token refuses.
    pub fn key_encryption_key_facts(&self, key: &KeyEncryptionKey) -> Result<KeyFacts, Error> {
        self.facts(key.handle, &key.label)
    }

    #[cfg(feature = "conformance")]
    /// Whether the token gives out the secret value of `key` (`CKA_VALUE`); `Err` with the
    /// return code when it refuses, as it must for a sensitive key.
    ///
    /// # Errors
    ///
    /// [`Error::Key`] with the token's refusal.
    pub fn read_secret_value(&self, key: &KeyEncryptionKey) -> Result<Vec<u8>, Error> {
        self.attribute_bytes(key.handle, AttributeType::Value, &key.label)
    }

    #[cfg(feature = "conformance")]
    /// Asks the token to decrypt with the private signing key, which it must refuse.
    ///
    /// # Errors
    ///
    /// [`Error::Key`] with the token's refusal.
    pub fn misuse_signing_key(&self, key: &SigningKey) -> Result<Vec<u8>, Error> {
        let mut iv = [0u8; GCM_IV_LEN];
        let params = GcmParams::new(&mut iv, &[], GCM_TAG_BITS.into())
            .map_err(key_error("set the GCM parameters", &key.label))?;
        self.session
            .encrypt(&Mechanism::AesGcm(params), key.private, b"x")
            .map_err(key_error("encrypt with a signing key", &key.label))
    }

    #[cfg(feature = "conformance")]
    /// Asks the token to sign with the key-encryption key, which it must refuse.
    ///
    /// # Errors
    ///
    /// [`Error::Key`] with the token's refusal.
    pub fn misuse_key_encryption_key(&self, key: &KeyEncryptionKey) -> Result<Vec<u8>, Error> {
        self.session
            .sign(&Mechanism::Ecdsa, key.handle, &[0; 32])
            .map_err(key_error("sign with a key-encryption key", &key.label))
    }

    #[cfg(feature = "conformance")]
    fn facts(&self, handle: ObjectHandle, label: &str) -> Result<KeyFacts, Error> {
        let attributes = self
            .session
            .get_attributes(
                handle,
                &[
                    AttributeType::Sensitive,
                    AttributeType::AlwaysSensitive,
                    AttributeType::Extractable,
                    AttributeType::NeverExtractable,
                    AttributeType::Sign,
                    AttributeType::Encrypt,
                    AttributeType::Decrypt,
                    AttributeType::Wrap,
                    AttributeType::Unwrap,
                    AttributeType::Derive,
                ],
            )
            .map_err(key_error("read the key's attributes", label))?;
        let mut facts = KeyFacts::default();
        for attribute in attributes {
            match attribute {
                Attribute::Sensitive(v) => facts.sensitive = Some(v),
                Attribute::AlwaysSensitive(v) => facts.always_sensitive = Some(v),
                Attribute::Extractable(v) => facts.extractable = Some(v),
                Attribute::NeverExtractable(v) => facts.never_extractable = Some(v),
                Attribute::Sign(v) => facts.sign = Some(v),
                Attribute::Encrypt(v) => facts.encrypt = Some(v),
                Attribute::Decrypt(v) => facts.decrypt = Some(v),
                Attribute::Wrap(v) => facts.wrap = Some(v),
                Attribute::Unwrap(v) => facts.unwrap = Some(v),
                Attribute::Derive(v) => facts.derive = Some(v),
                _ => {}
            }
        }
        Ok(facts)
    }

    fn attribute_bytes(
        &self,
        handle: ObjectHandle,
        attribute: AttributeType,
        label: &str,
    ) -> Result<Vec<u8>, Error> {
        let found = self
            .session
            .get_attributes(handle, &[attribute])
            .map_err(key_error("read an attribute", label))?;
        for value in found {
            match value {
                Attribute::EcParams(bytes)
                | Attribute::EcPoint(bytes)
                | Attribute::Value(bytes) => {
                    return Ok(bytes);
                }
                _ => {}
            }
        }
        let mut reason = String::new();
        let _ = write!(reason, "{attribute:?}");
        Err(Error::Key {
            op: "read an attribute",
            key: label.to_owned(),
            rv: None,
            detail: format!("the token does not report {reason}"),
        })
    }
}
