//! Writing PKCS#12 the way OpenSSL 3 does by default: certificates in a PBES2-encrypted
//! safe, keys in shrouded key bags, both PBKDF2-HMAC-SHA-256 with AES-256-CBC, and an
//! HMAC-SHA-256 MAC. Files written so need no `-legacy` anywhere.

use der::asn1::{Any, BmpString, ObjectIdentifier, OctetString, SetOfVec};
use der::{Encode, Sequence};
use hmac::{KeyInit, Mac, SimpleHmac};
use sha2::Sha256;
use spki::AlgorithmIdentifierOwned;

use crate::asn1::{Attribute, DigestInfo, MacData};
use crate::kdf::{self, Purpose};
use crate::{Error, Pkcs12, oids};

/// PBKDF2 and MAC iterations, OpenSSL 3's default.
pub const ITERATIONS: u32 = 2048;

const SALT_LEN: usize = 16;
const MAC_SALT_LEN: usize = 8;

/// Encodes the certificates and keys of `p12`, with their attributes, protected by
/// `password`. `fill_random` must fill its buffer from a cryptographically secure
/// source; it supplies the salts and IVs.
///
/// # Errors
///
/// [`Error::Malformed`] if a key or certificate does not encode, which only happens for
/// input that did not come from [`decode`](crate::decode).
pub fn encode(
    p12: &Pkcs12,
    password: &str,
    mut fill_random: impl FnMut(&mut [u8]),
) -> Result<Vec<u8>, Error> {
    let mut encrypt = |plaintext: &[u8]| -> Result<(AlgorithmIdentifierOwned, Vec<u8>), Error> {
        let mut salt = [0u8; SALT_LEN];
        let mut iv = [0u8; 16];
        fill_random(&mut salt);
        fill_random(&mut iv);
        let params =
            pkcs5::pbes2::Parameters::generate_pbkdf2_sha256_aes256cbc(ITERATIONS, &salt, iv)
                .map_err(|e| Error::malformed("PBES2 parameters", e.to_string()))?;
        let ciphertext = params
            .encrypt(password.as_bytes(), plaintext)
            .map_err(|e| Error::malformed("PBES2 encryption", e.to_string()))?;
        let algorithm = AlgorithmIdentifierOwned {
            oid: oids::PBES2,
            parameters: Some(Any::encode_from(&params)?),
        };
        Ok((algorithm, ciphertext))
    };

    let mut cert_bags = Vec::new();
    for cert in &p12.certificates {
        let value = CertBagOut {
            cert_id: oids::X509_CERTIFICATE,
            cert_value: OctetString::new(cert.der.clone())?,
        };
        cert_bags.push(SafeBagOut {
            id: oids::CERT_BAG,
            value: Any::encode_from(&value)?,
            attributes: attributes(cert.friendly_name.as_deref(), cert.local_key_id.as_deref())?,
        });
    }
    let mut key_bags = Vec::new();
    for key in &p12.keys {
        let (algorithm, ciphertext) = encrypt(&key.pkcs8)?;
        let value = EncryptedPrivateKeyInfoOut {
            encryption_algorithm: algorithm,
            encrypted_data: OctetString::new(ciphertext)?,
        };
        key_bags.push(SafeBagOut {
            id: oids::SHROUDED_KEY_BAG,
            value: Any::encode_from(&value)?,
            attributes: attributes(key.friendly_name.as_deref(), key.local_key_id.as_deref())?,
        });
    }

    let mut safes = Vec::new();
    if !cert_bags.is_empty() {
        let (algorithm, ciphertext) = encrypt(&cert_bags.to_der()?)?;
        let encrypted = EncryptedDataOut {
            version: 0,
            info: EncryptedContentInfoOut {
                content_type: oids::DATA,
                algorithm,
                encrypted_content: OctetString::new(ciphertext)?,
            },
        };
        safes.push(ContentInfoOut {
            content_type: oids::ENCRYPTED_DATA,
            content: Any::encode_from(&encrypted)?,
        });
    }
    if !key_bags.is_empty() {
        safes.push(ContentInfoOut {
            content_type: oids::DATA,
            content: Any::encode_from(&OctetString::new(key_bags.to_der()?)?)?,
        });
    }
    let auth_safe = safes.to_der()?;

    let mut mac_salt = [0u8; MAC_SALT_LEN];
    fill_random(&mut mac_salt);
    let mac_key = kdf::derive::<Sha256>(
        &kdf::bmp_password(password),
        &mac_salt,
        ITERATIONS,
        Purpose::Mac,
        32,
    );
    let mut mac = <SimpleHmac<Sha256> as KeyInit>::new_from_slice(&mac_key)
        .map_err(|_| Error::malformed("MAC key", "rejected"))?;
    mac.update(&auth_safe);
    let mac_data = MacData {
        mac: DigestInfo {
            algorithm: AlgorithmIdentifierOwned {
                oid: oids::SHA256,
                parameters: Some(Any::null()),
            },
            digest: OctetString::new(mac.finalize().into_bytes().to_vec())?,
        },
        mac_salt: OctetString::new(mac_salt.to_vec())?,
        iterations: ITERATIONS,
    };

    Ok(PfxOut {
        version: 3,
        auth_safe: ContentInfoOut {
            content_type: oids::DATA,
            content: Any::encode_from(&OctetString::new(auth_safe)?)?,
        },
        mac_data,
    }
    .to_der()?)
}

fn attributes(
    friendly_name: Option<&str>,
    local_key_id: Option<&[u8]>,
) -> Result<Option<SetOfVec<Attribute>>, Error> {
    let mut set = SetOfVec::new();
    if let Some(name) = friendly_name {
        set.insert(Attribute {
            attr_id: oids::FRIENDLY_NAME,
            attr_values: SetOfVec::from_iter([Any::encode_from(&BmpString::from_utf8(name)?)?])?,
        })?;
    }
    if let Some(id) = local_key_id {
        set.insert(Attribute {
            attr_id: oids::LOCAL_KEY_ID,
            attr_values: SetOfVec::from_iter([Any::encode_from(&OctetString::new(id.to_vec())?)?])?,
        })?;
    }
    Ok((!set.is_empty()).then_some(set))
}

/// The DER-only counterparts of the structures in `asn1`, which decode BER by hand and
/// therefore have no encoders.
#[derive(Sequence)]
struct PfxOut {
    version: u8,
    auth_safe: ContentInfoOut,
    mac_data: MacData,
}

#[derive(Sequence)]
struct ContentInfoOut {
    content_type: ObjectIdentifier,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT")]
    content: Any,
}

#[derive(Sequence)]
struct EncryptedDataOut {
    version: u8,
    info: EncryptedContentInfoOut,
}

#[derive(Sequence)]
struct EncryptedContentInfoOut {
    content_type: ObjectIdentifier,
    algorithm: AlgorithmIdentifierOwned,
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT")]
    encrypted_content: OctetString,
}

#[derive(Sequence)]
struct SafeBagOut {
    id: ObjectIdentifier,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT")]
    value: Any,
    attributes: Option<SetOfVec<Attribute>>,
}

#[derive(Sequence)]
struct CertBagOut {
    cert_id: ObjectIdentifier,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT")]
    cert_value: OctetString,
}

#[derive(Sequence)]
struct EncryptedPrivateKeyInfoOut {
    encryption_algorithm: AlgorithmIdentifierOwned,
    encrypted_data: OctetString,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode;

    /// A counter as the random source: deterministic, and never zero for the salts.
    fn counter() -> impl FnMut(&mut [u8]) {
        let mut next = 1u8;
        move |buf: &mut [u8]| {
            for byte in buf {
                *byte = next;
                next = next.wrapping_add(1);
            }
        }
    }

    #[test]
    fn round_trips_through_decode() {
        let fixture = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/legacy.p12"
        ))
        .unwrap();
        let original = decode(&fixture, "test1234").unwrap();
        let encoded = encode(&original, "00", counter()).unwrap();
        let again = decode(&encoded, "00").unwrap();
        assert_eq!(again.certificates, original.certificates);
        assert_eq!(again.keys.len(), original.keys.len());
        assert_eq!(*again.keys[0].pkcs8, *original.keys[0].pkcs8);
        assert_eq!(again.keys[0].local_key_id, original.keys[0].local_key_id);
        assert_eq!(again.pairs(), original.pairs());
        let mac = again.mac.unwrap();
        assert_eq!(
            (mac.digest.as_str(), mac.iterations),
            ("SHA-256", ITERATIONS)
        );
        assert!(
            again
                .encryption
                .iter()
                .all(|e| e.algorithm == "PBES2 AES-256-CBC")
        );
        assert!(matches!(decode(&encoded, "wrong"), Err(Error::MacMismatch)));
    }
}
