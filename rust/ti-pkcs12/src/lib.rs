//! PKCS#12 (RFC 7292) decoding for the identities of the gematik Telematikinfrastruktur:
//! the `.p12` files of SMC-B, HBA and component test cards and of soft keys.
//!
//! ```no_run
//! # fn demo(bytes: &[u8]) -> Result<(), ti_pkcs12::Error> {
//! let p12 = ti_pkcs12::decode(bytes, "00")?;
//! for pair in p12.pairs() {
//!     let certificate = &p12.certificates[pair.certificate];
//!     println!("{:?} has its key", certificate.friendly_name);
//! }
//! # Ok(()) }
//! ```
//!
//! What it reads:
//! - DER and BER: Java keystores and card vendors write indefinite lengths and
//!   constructed strings, which `der`'s BER mode decodes, so no external converter is
//!   needed (the Go module shells out to OpenSSL for these).
//! - The password integrity mode: HMAC-SHA-1/-224/-256/-384/-512 with the PKCS#12 KDF,
//!   checked over the auth-safe octets as received, before anything inside is parsed.
//! - Encryption: PBES2 (PBKDF2, AES-CBC) through `pkcs5`, and with the `legacy` feature
//!   (default) the PKCS#12 PBEs with 3DES and RC2 that OpenSSL's `-legacy` and many
//!   vendor files still use.
//! - Bags: certificates (X.509), shrouded key bags, plain key bags, nested safe
//!   contents; the `friendlyName` and `localKeyId` attributes.
//!
//! What it does not: public-key integrity mode (a signed auth safe), secret and CRL
//! bags, PBMAC1. Keys stay PKCS#8 DER in zeroized memory; the crate does no key
//! cryptography.

mod asn1;
mod decrypt;
mod kdf;
mod mac;

use core::fmt;

use der::Decode;
use der::asn1::{Any, ObjectIdentifier};
use zeroize::Zeroizing;

use crate::asn1::{CertBag, Content, ContentInfo, EncryptedPrivateKeyInfo, Pfx, SafeBag, reparse};

/// The object identifiers of RFC 7292 and the algorithms PKCS#12 files use.
pub mod oids {
    use der::asn1::ObjectIdentifier;

    /// `id-data` (PKCS#7).
    pub const DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1");
    /// `id-encryptedData` (PKCS#7).
    pub const ENCRYPTED_DATA: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.6");
    /// `keyBag`.
    pub const KEY_BAG: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.12.10.1.1");
    /// `pkcs8ShroudedKeyBag`.
    pub const SHROUDED_KEY_BAG: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.12.10.1.2");
    /// `certBag`.
    pub const CERT_BAG: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.12.10.1.3");
    /// `safeContentsBag`.
    pub const SAFE_CONTENTS_BAG: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.12.10.1.6");
    /// `x509Certificate` (the certificate type of a cert bag).
    pub const X509_CERTIFICATE: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.22.1");
    /// `friendlyName`.
    pub const FRIENDLY_NAME: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.20");
    /// `localKeyId`.
    pub const LOCAL_KEY_ID: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.21");
    /// PBES2 (RFC 8018).
    pub const PBES2: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.5.13");
    /// `pbeWithSHAAnd3-KeyTripleDES-CBC`.
    pub const PBE_SHA1_3DES: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.12.1.3");
    /// `pbeWithSHAAnd2-KeyTripleDES-CBC`.
    pub const PBE_SHA1_2DES: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.12.1.4");
    /// `pbeWithSHAAnd128BitRC2-CBC`.
    pub const PBE_SHA1_RC2_128: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.12.1.5");
    /// `pbewithSHAAnd40BitRC2-CBC`.
    pub const PBE_SHA1_RC2_40: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.12.1.6");
    /// SHA-1.
    pub const SHA1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.14.3.2.26");
    /// SHA-224.
    pub const SHA224: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.4");
    /// SHA-256.
    pub const SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
    /// SHA-384.
    pub const SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2");
    /// SHA-512.
    pub const SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.3");
}

/// Why a file could not be decoded.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The bytes are not a PKCS#12 structure, or one of its parts does not parse.
    #[error("malformed {what}: {reason}")]
    Malformed {
        /// The part that failed.
        what: &'static str,
        /// Why.
        reason: String,
    },
    /// The integrity MAC does not match: a wrong password, or an altered file.
    #[error("MAC mismatch: wrong password or altered file")]
    MacMismatch,
    /// Decryption produced no valid plaintext: a wrong password (in files without a
    /// MAC) or corrupt data.
    #[error("decryption failed: wrong password or corrupt data")]
    DecryptFailed,
    /// An algorithm or mode this crate does not implement.
    #[error("unsupported algorithm or mode {0}")]
    UnsupportedAlgorithm(ObjectIdentifier),
}

impl Error {
    fn malformed(what: &'static str, reason: impl Into<String>) -> Self {
        Error::Malformed {
            what,
            reason: reason.into(),
        }
    }
}

impl From<der::Error> for Error {
    fn from(error: der::Error) -> Self {
        Error::malformed("ASN.1", error.to_string())
    }
}

/// A decoded PKCS#12 file.
#[derive(Clone, Debug, Default)]
pub struct Pkcs12 {
    /// The certificates, in file order.
    pub certificates: Vec<CertificateBag>,
    /// The private keys, in file order.
    pub keys: Vec<KeyBag>,
    /// The integrity MAC, if the file has one.
    pub mac: Option<MacInfo>,
    /// The encryption of each encrypted safe and shrouded key, in file order: what the
    /// file is protected with.
    pub encryption: Vec<String>,
}

/// A certificate bag.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertificateBag {
    /// The certificate, DER.
    pub der: Vec<u8>,
    /// The `friendlyName` attribute.
    pub friendly_name: Option<String>,
    /// The `localKeyId` attribute, which ties a certificate to its key.
    pub local_key_id: Option<Vec<u8>>,
}

/// A private key bag, decrypted.
#[derive(Clone)]
pub struct KeyBag {
    /// The key as PKCS#8 `PrivateKeyInfo`, DER; zeroized on drop.
    pub pkcs8: Zeroizing<Vec<u8>>,
    /// The `friendlyName` attribute.
    pub friendly_name: Option<String>,
    /// The `localKeyId` attribute.
    pub local_key_id: Option<Vec<u8>>,
}

impl fmt::Debug for KeyBag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyBag")
            .field("pkcs8", &"<redacted>")
            .field("friendly_name", &self.friendly_name)
            .field("local_key_id", &self.local_key_id)
            .finish()
    }
}

impl KeyBag {
    /// The key's algorithm and, for EC keys, its curve, from the PKCS#8 header.
    pub fn algorithm(&self) -> Option<(ObjectIdentifier, Option<ObjectIdentifier>)> {
        let info = pkcs8::PrivateKeyInfoRef::from_der(&self.pkcs8).ok()?;
        let curve = info
            .algorithm
            .parameters
            .and_then(|p| p.decode_as::<ObjectIdentifier>().ok());
        Some((info.algorithm.oid, curve))
    }
}

/// The integrity MAC of a file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MacInfo {
    /// The digest, e.g. `SHA-256`.
    pub digest: String,
    /// KDF iterations.
    pub iterations: u32,
}

/// A certificate and its private key, as indices into [`Pkcs12::certificates`] and
/// [`Pkcs12::keys`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pair {
    /// Index into [`Pkcs12::certificates`].
    pub certificate: usize,
    /// Index into [`Pkcs12::keys`].
    pub key: usize,
}

impl Pkcs12 {
    /// The certificates that have their private key in the file, matched by
    /// `localKeyId`, the attribute PKCS#12 writers set for exactly this.
    pub fn pairs(&self) -> Vec<Pair> {
        self.certificates
            .iter()
            .enumerate()
            .filter_map(|(certificate, cert)| {
                let id = cert.local_key_id.as_deref()?;
                let key = self
                    .keys
                    .iter()
                    .position(|key| key.local_key_id.as_deref() == Some(id))?;
                Some(Pair { certificate, key })
            })
            .collect()
    }
}

/// Whether `bytes` look like a PKCS#12 file: a SEQUENCE (DER or BER) starting with
/// version 3. Cheap, for telling `.p12` input from certificates.
pub fn is_pkcs12(bytes: &[u8]) -> bool {
    let Some((&0x30, rest)) = bytes.split_first() else {
        return false;
    };
    let body = match rest.split_first() {
        Some((&0x80, body)) => body,
        Some((&len, body)) if len < 0x80 => body,
        Some((&len, body)) => body.get(usize::from(len & 0x7f)..).unwrap_or_default(),
        None => return false,
    };
    body.starts_with(&[0x02, 0x01, 0x03])
}

/// Decodes `bytes` with `password`: checks the MAC (if present), decrypts every
/// encrypted safe and shrouded key, and collects certificates and keys.
///
/// # Errors
///
/// [`Error::MacMismatch`] for a wrong password, [`Error::DecryptFailed`] for a wrong
/// password in a file without a MAC, [`Error::Malformed`] for anything that does not
/// parse, [`Error::UnsupportedAlgorithm`] for modes and algorithms outside this crate.
pub fn decode(bytes: &[u8], password: &str) -> Result<Pkcs12, Error> {
    if !is_pkcs12(bytes) {
        return Err(Error::malformed("PFX", "not a PKCS#12 file"));
    }
    let pfx = Pfx::from_ber(bytes)?;
    if pfx.version != 3 {
        return Err(Error::malformed("PFX", format!("version {}", pfx.version)));
    }
    if pfx.auth_safe.content_type != oids::DATA {
        // A signed auth safe: public-key integrity mode.
        return Err(Error::UnsupportedAlgorithm(pfx.auth_safe.content_type));
    }
    let Content::Data(auth_safe) = &pfx.auth_safe.content else {
        return Err(Error::malformed("PFX", "authSafe without content"));
    };

    let mut p12 = Pkcs12::default();
    if let Some(mac_data) = &pfx.mac_data {
        mac::verify(mac_data, &kdf::bmp_password(password), auth_safe)?;
        p12.mac = Some(MacInfo {
            digest: mac::name(mac_data.mac.algorithm.oid)
                .map_or_else(|| mac_data.mac.algorithm.oid.to_string(), str::to_owned),
            iterations: mac_data.iterations,
        });
    }

    for safe in Vec::<ContentInfo>::from_ber(auth_safe)? {
        let contents = match safe.content {
            Content::Data(octets) => Zeroizing::new(octets),
            Content::Encrypted(encrypted) => {
                p12.encryption.push(decrypt::name(&encrypted.algorithm));
                decrypt::decrypt(&encrypted.algorithm, password, &encrypted.ciphertext)?
            }
            // Enveloped safes (public-key privacy mode) need the recipient's key.
            Content::Other => return Err(Error::UnsupportedAlgorithm(safe.content_type)),
        };
        collect(&Vec::<SafeBag>::from_ber(&contents)?, password, &mut p12)?;
    }
    Ok(p12)
}

fn collect(bags: &[SafeBag], password: &str, p12: &mut Pkcs12) -> Result<(), Error> {
    for bag in bags {
        let (friendly_name, local_key_id) = attributes(bag);
        match bag.id {
            oids::CERT_BAG => {
                let cert: CertBag = reparse(&bag.value)?;
                if cert.cert_id != oids::X509_CERTIFICATE {
                    return Err(Error::UnsupportedAlgorithm(cert.cert_id));
                }
                p12.certificates.push(CertificateBag {
                    der: cert.cert_value.into_bytes().into_vec(),
                    friendly_name,
                    local_key_id,
                });
            }
            oids::SHROUDED_KEY_BAG => {
                let shrouded: EncryptedPrivateKeyInfo = reparse(&bag.value)?;
                p12.encryption
                    .push(decrypt::name(&shrouded.encryption_algorithm));
                let pkcs8 = decrypt::decrypt(
                    &shrouded.encryption_algorithm,
                    password,
                    shrouded.encrypted_data.as_bytes(),
                )?;
                p12.keys.push(KeyBag {
                    pkcs8,
                    friendly_name,
                    local_key_id,
                });
            }
            oids::KEY_BAG => {
                p12.keys.push(KeyBag {
                    pkcs8: Zeroizing::new(der::Encode::to_der(&bag.value)?),
                    friendly_name,
                    local_key_id,
                });
            }
            oids::SAFE_CONTENTS_BAG => {
                collect(&reparse::<Vec<SafeBag>>(&bag.value)?, password, p12)?;
            }
            // CRL, secret and unknown bags carry nothing an identity needs.
            _ => {}
        }
    }
    Ok(())
}

/// `friendlyName` (a BMPString) and `localKeyId` (an OCTET STRING) of a bag.
fn attributes(bag: &SafeBag) -> (Option<String>, Option<Vec<u8>>) {
    let mut friendly_name = None;
    let mut local_key_id = None;
    for attribute in bag.attributes.iter().flat_map(|set| set.iter()) {
        let Some(value) = attribute.attr_values.iter().next() else {
            continue;
        };
        match attribute.attr_id {
            oids::FRIENDLY_NAME => friendly_name = bmp_string(value),
            oids::LOCAL_KEY_ID => local_key_id = Some(value.value().to_vec()),
            _ => {}
        }
    }
    (friendly_name, local_key_id)
}

fn bmp_string(value: &Any) -> Option<String> {
    let (pairs, rest) = value.value().as_chunks::<2>();
    if !rest.is_empty() {
        return None;
    }
    let units: Vec<u16> = pairs.iter().map(|pair| u16::from_be_bytes(*pair)).collect();
    String::from_utf16(&units).ok()
}
