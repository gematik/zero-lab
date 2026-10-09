//! The registry: which names a program knows and what each one means.
//!
//! Entries are data: the key type and curve an algorithm needs, the lengths a key or
//! nonce must have, and whether jwz implements it ([`Support`]). Policies decide which
//! of the known names a parse accepts; the registry only says what a name is.

use alloc::vec::Vec;
use core::fmt;

use super::names::{
    ContentEncryptionAlgorithm, Curve, HashAlgorithm, KeyEncryptionAlgorithm, KeyType,
    SignatureAlgorithm,
};

/// Whether an algorithm can be used in this build.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Support {
    /// Implemented by jwz or by the crate that registered it.
    Available,
    /// Known by name only (RSA in milestone 1, post-quantum, PBES2): parsing reports
    /// it as unsupported instead of unknown.
    Reserved,
}

/// A JWS algorithm.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignatureEntry {
    /// The `alg` value.
    pub alg: SignatureAlgorithm,
    /// The `kty` a key for it must have.
    pub key_type: KeyType,
    /// The `crv` a key for it must have; `None` where the key type has no curve, or
    /// where the key's own `crv` selects it (`EdDSA`, RFC 8037 §3.1).
    pub curve: Option<Curve>,
    /// The hash it is defined with; `None` for pure EdDSA.
    pub hash: Option<HashAlgorithm>,
    /// Whether it is usable.
    pub support: Support,
}

/// How a JWE key management algorithm determines the content encryption key
/// (RFC 7516 §2, "Key Management Mode").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeyManagementMode {
    /// The shared key is the CEK (`dir`).
    DirectEncryption,
    /// ECDH-ES yields the CEK itself.
    DirectKeyAgreement,
    /// The CEK is wrapped with a symmetric key of `kek_len` bytes.
    KeyWrapping {
        /// Key encryption key length in bytes.
        kek_len: usize,
    },
    /// ECDH-ES yields a key of `kek_len` bytes that wraps the CEK.
    KeyAgreementWithKeyWrapping {
        /// Key encryption key length in bytes.
        kek_len: usize,
    },
    /// The CEK is encrypted to a public key (RSA).
    KeyEncryption,
    /// The CEK is wrapped with a key derived from a password (PBES2).
    PasswordBased,
}

/// A JWE key management algorithm.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyEncryptionEntry {
    /// The `alg` value.
    pub alg: KeyEncryptionAlgorithm,
    /// How it determines the CEK.
    pub mode: KeyManagementMode,
    /// Whether it is usable.
    pub support: Support,
}

/// The construction of a content encryption algorithm.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ContentEncryptionKind {
    /// An AEAD cipher (AES-GCM).
    Aead,
    /// AES-CBC with HMAC (RFC 7518 §5.2).
    CbcHmac,
}

/// A JWE content encryption algorithm.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ContentEncryptionEntry {
    /// The `enc` value.
    pub enc: ContentEncryptionAlgorithm,
    /// Its construction.
    pub kind: ContentEncryptionKind,
    /// CEK length in bytes.
    pub key_len: usize,
    /// Initialization vector length in bytes.
    pub iv_len: usize,
    /// Authentication tag length in bytes.
    pub tag_len: usize,
    /// Whether it is usable.
    pub support: Support,
}

/// A curve a JWK can name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CurveEntry {
    /// The `crv` value.
    pub crv: Curve,
    /// The `kty` of keys on it.
    pub key_type: KeyType,
    /// Length in bytes of one coordinate (`x`, `y`, `d`), fixed by RFC 7518 §6.2.1.2.
    pub coordinate_len: usize,
    /// Whether it is usable.
    pub support: Support,
}

/// Why a registration was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum RegistryError {
    /// The name is already registered; registrations never replace each other.
    Duplicate(&'static str),
    /// `none` in any casing: unsecured JWS is not representable (ADR 0001, principle 5).
    NoneAlgorithm,
    /// The name is empty.
    EmptyName,
}

impl fmt::Display for RegistryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RegistryError::Duplicate(name) => write!(f, "{name} is already registered"),
            RegistryError::NoneAlgorithm => f.write_str("the algorithm none cannot be registered"),
            RegistryError::EmptyName => f.write_str("an algorithm name must not be empty"),
        }
    }
}

impl core::error::Error for RegistryError {}

/// The known algorithms and curves.
#[derive(Clone, Debug, Default)]
pub struct Registry {
    signatures: Vec<SignatureEntry>,
    key_encryption: Vec<KeyEncryptionEntry>,
    content_encryption: Vec<ContentEncryptionEntry>,
    curves: Vec<CurveEntry>,
}

/// HMAC is implemented behind the `hmac` feature only.
const HMAC: Support = if cfg!(feature = "hmac") {
    Support::Available
} else {
    Support::Reserved
};

/// RFC 7518 §3.1 and RFC 8037 §3.1, with what jwz implements in milestone 1.
const STANDARD_SIGNATURES: &[SignatureEntry] = &[
    sig(
        SignatureAlgorithm::HS256,
        KeyType::OCT,
        None,
        Some(HashAlgorithm::Sha256),
        HMAC,
    ),
    sig(
        SignatureAlgorithm::HS384,
        KeyType::OCT,
        None,
        Some(HashAlgorithm::Sha384),
        HMAC,
    ),
    sig(
        SignatureAlgorithm::HS512,
        KeyType::OCT,
        None,
        Some(HashAlgorithm::Sha512),
        HMAC,
    ),
    sig(
        SignatureAlgorithm::RS256,
        KeyType::RSA,
        None,
        Some(HashAlgorithm::Sha256),
        Support::Reserved,
    ),
    sig(
        SignatureAlgorithm::RS384,
        KeyType::RSA,
        None,
        Some(HashAlgorithm::Sha384),
        Support::Reserved,
    ),
    sig(
        SignatureAlgorithm::RS512,
        KeyType::RSA,
        None,
        Some(HashAlgorithm::Sha512),
        Support::Reserved,
    ),
    sig(
        SignatureAlgorithm::ES256,
        KeyType::EC,
        Some(Curve::P256),
        Some(HashAlgorithm::Sha256),
        Support::Available,
    ),
    sig(
        SignatureAlgorithm::ES384,
        KeyType::EC,
        Some(Curve::P384),
        Some(HashAlgorithm::Sha384),
        Support::Reserved,
    ),
    sig(
        SignatureAlgorithm::ES512,
        KeyType::EC,
        Some(Curve::P521),
        Some(HashAlgorithm::Sha512),
        Support::Reserved,
    ),
    sig(
        SignatureAlgorithm::PS256,
        KeyType::RSA,
        None,
        Some(HashAlgorithm::Sha256),
        Support::Reserved,
    ),
    sig(
        SignatureAlgorithm::PS384,
        KeyType::RSA,
        None,
        Some(HashAlgorithm::Sha384),
        Support::Reserved,
    ),
    sig(
        SignatureAlgorithm::PS512,
        KeyType::RSA,
        None,
        Some(HashAlgorithm::Sha512),
        Support::Reserved,
    ),
    sig(
        SignatureAlgorithm::EDDSA,
        KeyType::OKP,
        None,
        None,
        Support::Available,
    ),
    sig(
        SignatureAlgorithm::ML_DSA_44,
        KeyType::new("AKP"),
        None,
        None,
        Support::Reserved,
    ),
    sig(
        SignatureAlgorithm::ML_DSA_65,
        KeyType::new("AKP"),
        None,
        None,
        Support::Reserved,
    ),
    sig(
        SignatureAlgorithm::ML_DSA_87,
        KeyType::new("AKP"),
        None,
        None,
        Support::Reserved,
    ),
];

/// RFC 7518 §4.1.
const STANDARD_KEY_ENCRYPTION: &[KeyEncryptionEntry] = &[
    kek(
        KeyEncryptionAlgorithm::RSA1_5,
        KeyManagementMode::KeyEncryption,
        Support::Reserved,
    ),
    kek(
        KeyEncryptionAlgorithm::RSA_OAEP,
        KeyManagementMode::KeyEncryption,
        Support::Reserved,
    ),
    kek(
        KeyEncryptionAlgorithm::RSA_OAEP_256,
        KeyManagementMode::KeyEncryption,
        Support::Reserved,
    ),
    kek(
        KeyEncryptionAlgorithm::A128KW,
        KeyManagementMode::KeyWrapping { kek_len: 16 },
        Support::Available,
    ),
    kek(
        KeyEncryptionAlgorithm::A192KW,
        KeyManagementMode::KeyWrapping { kek_len: 24 },
        Support::Available,
    ),
    kek(
        KeyEncryptionAlgorithm::A256KW,
        KeyManagementMode::KeyWrapping { kek_len: 32 },
        Support::Available,
    ),
    kek(
        KeyEncryptionAlgorithm::DIR,
        KeyManagementMode::DirectEncryption,
        Support::Available,
    ),
    kek(
        KeyEncryptionAlgorithm::ECDH_ES,
        KeyManagementMode::DirectKeyAgreement,
        Support::Available,
    ),
    kek(
        KeyEncryptionAlgorithm::ECDH_ES_A128KW,
        KeyManagementMode::KeyAgreementWithKeyWrapping { kek_len: 16 },
        Support::Available,
    ),
    kek(
        KeyEncryptionAlgorithm::ECDH_ES_A192KW,
        KeyManagementMode::KeyAgreementWithKeyWrapping { kek_len: 24 },
        Support::Available,
    ),
    kek(
        KeyEncryptionAlgorithm::ECDH_ES_A256KW,
        KeyManagementMode::KeyAgreementWithKeyWrapping { kek_len: 32 },
        Support::Available,
    ),
    kek(
        KeyEncryptionAlgorithm::A128GCMKW,
        KeyManagementMode::KeyWrapping { kek_len: 16 },
        Support::Reserved,
    ),
    kek(
        KeyEncryptionAlgorithm::A192GCMKW,
        KeyManagementMode::KeyWrapping { kek_len: 24 },
        Support::Reserved,
    ),
    kek(
        KeyEncryptionAlgorithm::A256GCMKW,
        KeyManagementMode::KeyWrapping { kek_len: 32 },
        Support::Reserved,
    ),
    kek(
        KeyEncryptionAlgorithm::PBES2_HS256_A128KW,
        KeyManagementMode::PasswordBased,
        Support::Reserved,
    ),
    kek(
        KeyEncryptionAlgorithm::PBES2_HS384_A192KW,
        KeyManagementMode::PasswordBased,
        Support::Reserved,
    ),
    kek(
        KeyEncryptionAlgorithm::PBES2_HS512_A256KW,
        KeyManagementMode::PasswordBased,
        Support::Reserved,
    ),
    kek(
        KeyEncryptionAlgorithm::ML_KEM_512,
        KeyManagementMode::KeyEncryption,
        Support::Reserved,
    ),
    kek(
        KeyEncryptionAlgorithm::ML_KEM_768,
        KeyManagementMode::KeyEncryption,
        Support::Reserved,
    ),
    kek(
        KeyEncryptionAlgorithm::ML_KEM_1024,
        KeyManagementMode::KeyEncryption,
        Support::Reserved,
    ),
];

/// RFC 7518 §5.1; CBC-HMAC is known but not implemented (refused by the default policy).
const STANDARD_CONTENT_ENCRYPTION: &[ContentEncryptionEntry] = &[
    enc(
        ContentEncryptionAlgorithm::A128CBC_HS256,
        ContentEncryptionKind::CbcHmac,
        32,
        16,
        16,
        Support::Reserved,
    ),
    enc(
        ContentEncryptionAlgorithm::A192CBC_HS384,
        ContentEncryptionKind::CbcHmac,
        48,
        16,
        24,
        Support::Reserved,
    ),
    enc(
        ContentEncryptionAlgorithm::A256CBC_HS512,
        ContentEncryptionKind::CbcHmac,
        64,
        16,
        32,
        Support::Reserved,
    ),
    // RFC 7518 §5.3: 96-bit IV, 128-bit tag.
    enc(
        ContentEncryptionAlgorithm::A128GCM,
        ContentEncryptionKind::Aead,
        16,
        12,
        16,
        Support::Available,
    ),
    enc(
        ContentEncryptionAlgorithm::A192GCM,
        ContentEncryptionKind::Aead,
        24,
        12,
        16,
        Support::Available,
    ),
    enc(
        ContentEncryptionAlgorithm::A256GCM,
        ContentEncryptionKind::Aead,
        32,
        12,
        16,
        Support::Available,
    ),
];

/// RFC 7518 §6.2.1.1 and RFC 8037 §2.
const STANDARD_CURVES: &[CurveEntry] = &[
    crv(Curve::P256, KeyType::EC, 32, Support::Available),
    crv(Curve::P384, KeyType::EC, 48, Support::Reserved),
    crv(Curve::P521, KeyType::EC, 66, Support::Reserved),
    crv(Curve::ED25519, KeyType::OKP, 32, Support::Available),
    crv(Curve::ED448, KeyType::OKP, 57, Support::Reserved),
    crv(Curve::X25519, KeyType::OKP, 32, Support::Reserved),
    crv(Curve::X448, KeyType::OKP, 56, Support::Reserved),
];

const fn sig(
    alg: SignatureAlgorithm,
    key_type: KeyType,
    curve: Option<Curve>,
    hash: Option<HashAlgorithm>,
    support: Support,
) -> SignatureEntry {
    SignatureEntry {
        alg,
        key_type,
        curve,
        hash,
        support,
    }
}

const fn kek(
    alg: KeyEncryptionAlgorithm,
    mode: KeyManagementMode,
    support: Support,
) -> KeyEncryptionEntry {
    KeyEncryptionEntry { alg, mode, support }
}

const fn enc(
    enc: ContentEncryptionAlgorithm,
    kind: ContentEncryptionKind,
    key_len: usize,
    iv_len: usize,
    tag_len: usize,
    support: Support,
) -> ContentEncryptionEntry {
    ContentEncryptionEntry {
        enc,
        kind,
        key_len,
        iv_len,
        tag_len,
        support,
    }
}

const fn crv(crv: Curve, key_type: KeyType, coordinate_len: usize, support: Support) -> CurveEntry {
    CurveEntry {
        crv,
        key_type,
        coordinate_len,
        support,
    }
}

impl Registry {
    /// A registry that knows nothing.
    pub fn empty() -> Self {
        Registry::default()
    }

    /// The names of RFC 7518 and RFC 8037, with what jwz implements marked
    /// [`Support::Available`] and the rest [`Support::Reserved`].
    pub fn standard() -> Self {
        Registry {
            signatures: STANDARD_SIGNATURES.to_vec(),
            key_encryption: STANDARD_KEY_ENCRYPTION.to_vec(),
            content_encryption: STANDARD_CONTENT_ENCRYPTION.to_vec(),
            curves: STANDARD_CURVES.to_vec(),
        }
    }

    /// Adds a JWS algorithm.
    ///
    /// # Errors
    ///
    /// [`RegistryError::Duplicate`] if the name is known, [`RegistryError::NoneAlgorithm`]
    /// for `none`, [`RegistryError::EmptyName`] for an empty name.
    pub fn register_signature(&mut self, entry: SignatureEntry) -> Result<(), RegistryError> {
        check_name(entry.alg.as_str())?;
        if self.signature(entry.alg.as_str()).is_some() {
            return Err(RegistryError::Duplicate(entry.alg.as_str()));
        }
        self.signatures.push(entry);
        Ok(())
    }

    /// Adds a JWE key management algorithm.
    ///
    /// # Errors
    ///
    /// As [`register_signature`](Self::register_signature).
    pub fn register_key_encryption(
        &mut self,
        entry: KeyEncryptionEntry,
    ) -> Result<(), RegistryError> {
        check_name(entry.alg.as_str())?;
        if self.key_encryption(entry.alg.as_str()).is_some() {
            return Err(RegistryError::Duplicate(entry.alg.as_str()));
        }
        self.key_encryption.push(entry);
        Ok(())
    }

    /// Adds a JWE content encryption algorithm.
    ///
    /// # Errors
    ///
    /// As [`register_signature`](Self::register_signature).
    pub fn register_content_encryption(
        &mut self,
        entry: ContentEncryptionEntry,
    ) -> Result<(), RegistryError> {
        check_name(entry.enc.as_str())?;
        if self.content_encryption(entry.enc.as_str()).is_some() {
            return Err(RegistryError::Duplicate(entry.enc.as_str()));
        }
        self.content_encryption.push(entry);
        Ok(())
    }

    /// Adds a curve.
    ///
    /// # Errors
    ///
    /// As [`register_signature`](Self::register_signature).
    pub fn register_curve(&mut self, entry: CurveEntry) -> Result<(), RegistryError> {
        check_name(entry.crv.as_str())?;
        if self.curve(entry.crv.as_str()).is_some() {
            return Err(RegistryError::Duplicate(entry.crv.as_str()));
        }
        self.curves.push(entry);
        Ok(())
    }

    /// The JWS algorithm named `name`, compared case-sensitively; never `none`.
    pub fn signature(&self, name: &str) -> Option<&SignatureEntry> {
        if is_none(name) {
            return None;
        }
        self.signatures.iter().find(|e| e.alg.as_str() == name)
    }

    /// The JWE key management algorithm named `name`.
    pub fn key_encryption(&self, name: &str) -> Option<&KeyEncryptionEntry> {
        self.key_encryption.iter().find(|e| e.alg.as_str() == name)
    }

    /// The JWE content encryption algorithm named `name`.
    pub fn content_encryption(&self, name: &str) -> Option<&ContentEncryptionEntry> {
        self.content_encryption
            .iter()
            .find(|e| e.enc.as_str() == name)
    }

    /// The curve named `name`.
    pub fn curve(&self, name: &str) -> Option<&CurveEntry> {
        self.curves.iter().find(|e| e.crv.as_str() == name)
    }

    /// Every known JWS algorithm, in registration order.
    pub fn signatures(&self) -> &[SignatureEntry] {
        &self.signatures
    }

    /// Every known JWE key management algorithm, in registration order.
    pub fn key_encryptions(&self) -> &[KeyEncryptionEntry] {
        &self.key_encryption
    }

    /// Every known JWE content encryption algorithm, in registration order.
    pub fn content_encryptions(&self) -> &[ContentEncryptionEntry] {
        &self.content_encryption
    }

    /// Every known curve, in registration order.
    pub fn curves(&self) -> &[CurveEntry] {
        &self.curves
    }
}

/// RFC 7518 §3.6: `none` means an unsecured JWS; jwz refuses it in any casing.
fn is_none(name: &str) -> bool {
    name.eq_ignore_ascii_case("none")
}

fn check_name(name: &str) -> Result<(), RegistryError> {
    if name.is_empty() {
        return Err(RegistryError::EmptyName);
    }
    if is_none(name) {
        return Err(RegistryError::NoneAlgorithm);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_names_are_found_case_sensitively() {
        let registry = Registry::standard();
        let es256 = registry.signature("ES256").unwrap();
        assert_eq!(es256.curve, Some(Curve::P256));
        assert_eq!(es256.support, Support::Available);
        assert!(registry.signature("es256").is_none());
        assert_eq!(
            registry
                .content_encryption("A256GCM")
                .map(|e| (e.key_len, e.iv_len, e.tag_len)),
            Some((32, 12, 16))
        );
        assert_eq!(registry.curve("P-256").map(|e| e.coordinate_len), Some(32));
    }

    #[test]
    fn rfc_7518_3_6_none_is_unrepresentable_in_any_casing() {
        let registry = Registry::standard();
        for name in ["none", "None", "NONE", "nOnE"] {
            assert!(registry.signature(name).is_none(), "{name}");
        }
        let mut registry = Registry::empty();
        let entry = sig(
            SignatureAlgorithm::new("NoNe"),
            KeyType::OCT,
            None,
            None,
            Support::Available,
        );
        assert_eq!(
            registry.register_signature(entry),
            Err(RegistryError::NoneAlgorithm)
        );
    }

    #[test]
    fn registrations_never_replace_each_other() {
        let mut registry = Registry::standard();
        let again = sig(
            SignatureAlgorithm::ES256,
            KeyType::EC,
            Some(Curve::new("BP-256")),
            Some(HashAlgorithm::Sha256),
            Support::Available,
        );
        assert_eq!(
            registry.register_signature(again),
            Err(RegistryError::Duplicate("ES256"))
        );
        assert_eq!(
            registry.signature("ES256").unwrap().curve,
            Some(Curve::P256)
        );
    }

    #[test]
    fn reserved_names_are_known_but_not_available() {
        let registry = Registry::standard();
        assert_eq!(
            registry.signature("PS256").unwrap().support,
            Support::Reserved
        );
        assert_eq!(
            registry.key_encryption("RSA-OAEP").unwrap().support,
            Support::Reserved
        );
        assert_eq!(
            registry.signature("ML-DSA-65").unwrap().support,
            Support::Reserved
        );
        assert!(registry.signature("BP256R1").is_none());
    }
}
