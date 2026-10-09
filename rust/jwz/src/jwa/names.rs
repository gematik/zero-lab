//! The name types and the standard names of RFC 7518 and RFC 8037.
//!
//! `none` has no constant and cannot be registered (ADR 0001, principle 5): a token
//! that names it is refused by every registry lookup.

use core::fmt;
use core::hash::{Hash, Hasher};
use core::marker::PhantomData;

/// The category a [`Name`] belongs to; it keeps a curve name from being used where a
/// signature algorithm is expected.
pub trait Kind {
    /// What the name is, for `Debug` output.
    const LABEL: &'static str;
}

/// A wire name of one [`Kind`]. Names are case-sensitive (RFC 7515 §4.1.1, RFC 7516
/// §4.1.1) and compared by their text.
pub struct Name<K: Kind> {
    text: &'static str,
    kind: PhantomData<K>,
}

impl<K: Kind> Name<K> {
    /// The name `text`, as it appears on the wire.
    pub const fn new(text: &'static str) -> Self {
        Name {
            text,
            kind: PhantomData,
        }
    }

    /// The name as it appears on the wire.
    pub const fn as_str(self) -> &'static str {
        self.text
    }
}

// Written out instead of derived: a derive would require `K` itself to implement them.
impl<K: Kind> Clone for Name<K> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<K: Kind> Copy for Name<K> {}

impl<K: Kind> PartialEq for Name<K> {
    fn eq(&self, other: &Self) -> bool {
        self.text == other.text
    }
}

impl<K: Kind> Eq for Name<K> {}

impl<K: Kind> Hash for Name<K> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.text.hash(state);
    }
}

impl<K: Kind> fmt::Display for Name<K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.text)
    }
}

impl<K: Kind> fmt::Debug for Name<K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}({:?})", K::LABEL, self.text)
    }
}

/// Kind of [`SignatureAlgorithm`].
#[derive(Debug)]
pub enum Signature {}
/// Kind of [`KeyEncryptionAlgorithm`].
#[derive(Debug)]
pub enum KeyEncryption {}
/// Kind of [`ContentEncryptionAlgorithm`].
#[derive(Debug)]
pub enum ContentEncryption {}
/// Kind of [`Curve`].
#[derive(Debug)]
pub enum CurveName {}
/// Kind of [`KeyType`].
#[derive(Debug)]
pub enum KeyTypeName {}

impl Kind for Signature {
    const LABEL: &'static str = "SignatureAlgorithm";
}
impl Kind for KeyEncryption {
    const LABEL: &'static str = "KeyEncryptionAlgorithm";
}
impl Kind for ContentEncryption {
    const LABEL: &'static str = "ContentEncryptionAlgorithm";
}
impl Kind for CurveName {
    const LABEL: &'static str = "Curve";
}
impl Kind for KeyTypeName {
    const LABEL: &'static str = "KeyType";
}

/// A JWS `alg` value (RFC 7515 §4.1.1).
pub type SignatureAlgorithm = Name<Signature>;
/// A JWE `alg` value: how the content encryption key is determined (RFC 7516 §4.1.1).
pub type KeyEncryptionAlgorithm = Name<KeyEncryption>;
/// A JWE `enc` value: how the content is encrypted (RFC 7516 §4.1.2).
pub type ContentEncryptionAlgorithm = Name<ContentEncryption>;
/// A JWK `crv` value (RFC 7518 §6.2.1.1, RFC 8037 §2).
pub type Curve = Name<CurveName>;
/// A JWK `kty` value (RFC 7517 §4.1).
pub type KeyType = Name<KeyTypeName>;

// RFC 7518 §3.1: "alg" values for JWS. `none` is deliberately absent.
impl Name<Signature> {
    /// HMAC using SHA-256.
    pub const HS256: Self = Self::new("HS256");
    /// HMAC using SHA-384.
    pub const HS384: Self = Self::new("HS384");
    /// HMAC using SHA-512.
    pub const HS512: Self = Self::new("HS512");
    /// RSASSA-PKCS1-v1_5 using SHA-256.
    pub const RS256: Self = Self::new("RS256");
    /// RSASSA-PKCS1-v1_5 using SHA-384.
    pub const RS384: Self = Self::new("RS384");
    /// RSASSA-PKCS1-v1_5 using SHA-512.
    pub const RS512: Self = Self::new("RS512");
    /// ECDSA using P-256 and SHA-256.
    pub const ES256: Self = Self::new("ES256");
    /// ECDSA using P-384 and SHA-384.
    pub const ES384: Self = Self::new("ES384");
    /// ECDSA using P-521 and SHA-512.
    pub const ES512: Self = Self::new("ES512");
    /// RSASSA-PSS using SHA-256 and MGF1 with SHA-256.
    pub const PS256: Self = Self::new("PS256");
    /// RSASSA-PSS using SHA-384 and MGF1 with SHA-384.
    pub const PS384: Self = Self::new("PS384");
    /// RSASSA-PSS using SHA-512 and MGF1 with SHA-512.
    pub const PS512: Self = Self::new("PS512");
    // RFC 8037 §3.1: Edwards-curve signatures.
    /// EdDSA over the curve named in the key's `crv` (Ed25519 or Ed448).
    pub const EDDSA: Self = Self::new("EdDSA");
    // Reserved for post-quantum signatures (draft-ietf-cose-dilithium); not implemented.
    /// ML-DSA-44 (reserved).
    pub const ML_DSA_44: Self = Self::new("ML-DSA-44");
    /// ML-DSA-65 (reserved).
    pub const ML_DSA_65: Self = Self::new("ML-DSA-65");
    /// ML-DSA-87 (reserved).
    pub const ML_DSA_87: Self = Self::new("ML-DSA-87");
}

// RFC 7518 §4.1: "alg" values for JWE.
impl Name<KeyEncryption> {
    /// RSAES-PKCS1-v1_5.
    pub const RSA1_5: Self = Self::new("RSA1_5");
    /// RSAES OAEP using default parameters.
    pub const RSA_OAEP: Self = Self::new("RSA-OAEP");
    /// RSAES OAEP using SHA-256 and MGF1 with SHA-256.
    pub const RSA_OAEP_256: Self = Self::new("RSA-OAEP-256");
    /// AES Key Wrap with a 128-bit key.
    pub const A128KW: Self = Self::new("A128KW");
    /// AES Key Wrap with a 192-bit key.
    pub const A192KW: Self = Self::new("A192KW");
    /// AES Key Wrap with a 256-bit key.
    pub const A256KW: Self = Self::new("A256KW");
    /// Direct use of a shared symmetric key as the content encryption key.
    pub const DIR: Self = Self::new("dir");
    /// ECDH-ES using Concat KDF, the derived key used directly.
    pub const ECDH_ES: Self = Self::new("ECDH-ES");
    /// ECDH-ES using Concat KDF and AES Key Wrap with a 128-bit key.
    pub const ECDH_ES_A128KW: Self = Self::new("ECDH-ES+A128KW");
    /// ECDH-ES using Concat KDF and AES Key Wrap with a 192-bit key.
    pub const ECDH_ES_A192KW: Self = Self::new("ECDH-ES+A192KW");
    /// ECDH-ES using Concat KDF and AES Key Wrap with a 256-bit key.
    pub const ECDH_ES_A256KW: Self = Self::new("ECDH-ES+A256KW");
    /// Key wrapping with AES-GCM using a 128-bit key.
    pub const A128GCMKW: Self = Self::new("A128GCMKW");
    /// Key wrapping with AES-GCM using a 192-bit key.
    pub const A192GCMKW: Self = Self::new("A192GCMKW");
    /// Key wrapping with AES-GCM using a 256-bit key.
    pub const A256GCMKW: Self = Self::new("A256GCMKW");
    /// PBES2 with HMAC SHA-256 and A128KW wrapping.
    pub const PBES2_HS256_A128KW: Self = Self::new("PBES2-HS256+A128KW");
    /// PBES2 with HMAC SHA-384 and A192KW wrapping.
    pub const PBES2_HS384_A192KW: Self = Self::new("PBES2-HS384+A192KW");
    /// PBES2 with HMAC SHA-512 and A256KW wrapping.
    pub const PBES2_HS512_A256KW: Self = Self::new("PBES2-HS512+A256KW");
    // Reserved for post-quantum key encapsulation; not implemented.
    /// ML-KEM-512 (reserved).
    pub const ML_KEM_512: Self = Self::new("ML-KEM-512");
    /// ML-KEM-768 (reserved).
    pub const ML_KEM_768: Self = Self::new("ML-KEM-768");
    /// ML-KEM-1024 (reserved).
    pub const ML_KEM_1024: Self = Self::new("ML-KEM-1024");
}

// RFC 7518 §5.1: "enc" values for JWE.
impl Name<ContentEncryption> {
    /// AES-128-CBC with HMAC SHA-256.
    pub const A128CBC_HS256: Self = Self::new("A128CBC-HS256");
    /// AES-192-CBC with HMAC SHA-384.
    pub const A192CBC_HS384: Self = Self::new("A192CBC-HS384");
    /// AES-256-CBC with HMAC SHA-512.
    pub const A256CBC_HS512: Self = Self::new("A256CBC-HS512");
    /// AES-GCM with a 128-bit key.
    pub const A128GCM: Self = Self::new("A128GCM");
    /// AES-GCM with a 192-bit key.
    pub const A192GCM: Self = Self::new("A192GCM");
    /// AES-GCM with a 256-bit key.
    pub const A256GCM: Self = Self::new("A256GCM");
}

impl Name<CurveName> {
    // RFC 7518 §6.2.1.1: elliptic curves for EC keys.
    /// NIST P-256.
    pub const P256: Self = Self::new("P-256");
    /// NIST P-384.
    pub const P384: Self = Self::new("P-384");
    /// NIST P-521.
    pub const P521: Self = Self::new("P-521");
    // RFC 8037 §2: curves for OKP keys.
    /// Ed25519 signature curve.
    pub const ED25519: Self = Self::new("Ed25519");
    /// Ed448 signature curve.
    pub const ED448: Self = Self::new("Ed448");
    /// X25519 key agreement curve.
    pub const X25519: Self = Self::new("X25519");
    /// X448 key agreement curve.
    pub const X448: Self = Self::new("X448");
}

// RFC 7518 §6.1 and RFC 8037 §2: key types.
impl Name<KeyTypeName> {
    /// Elliptic curve keys.
    pub const EC: Self = Self::new("EC");
    /// RSA keys.
    pub const RSA: Self = Self::new("RSA");
    /// Octet sequences (symmetric keys).
    pub const OCT: Self = Self::new("oct");
    /// Octet key pairs (Edwards and Montgomery curves).
    pub const OKP: Self = Self::new("OKP");
}

/// The hash a signature algorithm or KDF is defined with.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum HashAlgorithm {
    /// SHA-256.
    Sha256,
    /// SHA-384.
    Sha384,
    /// SHA-512.
    Sha512,
}

impl HashAlgorithm {
    /// The digest length in bytes.
    pub const fn output_len(self) -> usize {
        match self {
            HashAlgorithm::Sha256 => 32,
            HashAlgorithm::Sha384 => 48,
            HashAlgorithm::Sha512 => 64,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;

    #[test]
    fn names_round_trip_and_debug_names_the_kind() {
        assert_eq!(SignatureAlgorithm::ES256.as_str(), "ES256");
        assert_eq!(format!("{}", Curve::P256), "P-256");
        assert_eq!(format!("{:?}", KeyType::OKP), "KeyType(\"OKP\")");
        assert_eq!(SignatureAlgorithm::new("ES256"), SignatureAlgorithm::ES256);
    }
}
