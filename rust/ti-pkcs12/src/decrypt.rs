//! Decryption of shrouded key bags and encrypted safes: PBES2 through `pkcs5`, and with
//! the `legacy` feature the PKCS#12 PBEs of RFC 7292 Appendix C.

use der::{Decode, Encode};
use spki::AlgorithmIdentifierOwned;
use zeroize::Zeroizing;

use crate::{Error, oids};

/// `ciphertext` decrypted under `algorithm` with `password`. PBES2 takes the password's
/// UTF-8 bytes (as OpenSSL does), the PKCS#12 PBEs its BMP form.
pub(crate) fn decrypt(
    algorithm: &AlgorithmIdentifierOwned,
    password: &str,
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    match algorithm.oid {
        oids::PBES2 => pbes2(algorithm, password, ciphertext),
        #[cfg(feature = "legacy")]
        oid if legacy::is_pkcs12_pbe(oid) => legacy::decrypt(algorithm, password, ciphertext),
        oid => Err(Error::UnsupportedAlgorithm(oid)),
    }
}

fn pbes2(
    algorithm: &AlgorithmIdentifierOwned,
    password: &str,
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let encoded = algorithm.to_der()?;
    let parsed = spki::AlgorithmIdentifierRef::from_der(&encoded)?;
    let scheme = pkcs5::EncryptionScheme::try_from(parsed)
        .map_err(|_| Error::UnsupportedAlgorithm(algorithm.oid))?;
    scheme
        .decrypt(password.as_bytes(), ciphertext)
        .map(Zeroizing::new)
        .map_err(|_| Error::DecryptFailed)
}

/// The display name of an encryption algorithm, e.g. `PBES2 AES-256-CBC` or
/// `PKCS#12 3DES`.
pub(crate) fn name(algorithm: &AlgorithmIdentifierOwned) -> String {
    match algorithm.oid {
        oids::PBES2 => {
            let cipher = algorithm
                .to_der()
                .ok()
                .and_then(|der| {
                    let parsed = spki::AlgorithmIdentifierRef::from_der(&der).ok()?;
                    let pkcs5::EncryptionScheme::Pbes2(params) =
                        pkcs5::EncryptionScheme::try_from(parsed).ok()?
                    else {
                        return None;
                    };
                    Some(params.encryption.oid().to_string())
                })
                .map(|oid| cipher_name(&oid).unwrap_or(&oid).to_owned())
                .unwrap_or_default();
            format!("PBES2 {cipher}").trim_end().to_owned()
        }
        oid => pkcs12_pbe_name(oid).map_or_else(|| oid.to_string(), str::to_owned),
    }
}

fn cipher_name(oid: &str) -> Option<&'static str> {
    Some(match oid {
        "2.16.840.1.101.3.4.1.2" => "AES-128-CBC",
        "2.16.840.1.101.3.4.1.22" => "AES-192-CBC",
        "2.16.840.1.101.3.4.1.42" => "AES-256-CBC",
        "1.2.840.113549.3.7" => "DES-EDE3-CBC",
        _ => return None,
    })
}

fn pkcs12_pbe_name(oid: der::asn1::ObjectIdentifier) -> Option<&'static str> {
    Some(match oid {
        oids::PBE_SHA1_3DES => "PKCS#12 3DES",
        oids::PBE_SHA1_2DES => "PKCS#12 2-key 3DES",
        oids::PBE_SHA1_RC2_128 => "PKCS#12 RC2-128",
        oids::PBE_SHA1_RC2_40 => "PKCS#12 RC2-40",
        _ => return None,
    })
}

#[cfg(feature = "legacy")]
mod legacy {
    use cbc::cipher::block_padding::Pkcs7;
    use cbc::cipher::{BlockModeDecrypt, InnerIvInit, KeyIvInit};
    use der::asn1::ObjectIdentifier;
    use sha1::Sha1;
    use spki::AlgorithmIdentifierOwned;
    use zeroize::Zeroizing;

    use crate::asn1::{PbeParams, reparse};
    use crate::kdf::{self, Purpose};
    use crate::{Error, oids};

    pub(super) fn is_pkcs12_pbe(oid: ObjectIdentifier) -> bool {
        matches!(
            oid,
            oids::PBE_SHA1_3DES
                | oids::PBE_SHA1_2DES
                | oids::PBE_SHA1_RC2_128
                | oids::PBE_SHA1_RC2_40
        )
    }

    /// RFC 7292 Appendix C: key and IV from the PKCS#12 KDF with SHA-1, then CBC with
    /// PKCS#7 padding.
    pub(super) fn decrypt(
        algorithm: &AlgorithmIdentifierOwned,
        password: &str,
        ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        let parameters = algorithm
            .parameters
            .as_ref()
            .ok_or_else(|| Error::malformed("PBE parameters", "missing"))?;
        let params: PbeParams = reparse(parameters)?;
        let password = kdf::bmp_password(password);
        let derive = |purpose, len| {
            kdf::derive::<Sha1>(
                &password,
                params.salt.as_bytes(),
                params.iterations,
                purpose,
                len,
            )
        };
        let iv = derive(Purpose::Iv, 8);
        let plaintext = match algorithm.oid {
            oids::PBE_SHA1_3DES => {
                let key = derive(Purpose::Key, 24);
                cbc::Decryptor::<des::TdesEde3>::new_from_slices(&key, &iv)
                    .map_err(|_| Error::DecryptFailed)?
                    .decrypt_padded_vec::<Pkcs7>(ciphertext)
            }
            oids::PBE_SHA1_2DES => {
                let key = derive(Purpose::Key, 16);
                cbc::Decryptor::<des::TdesEde2>::new_from_slices(&key, &iv)
                    .map_err(|_| Error::DecryptFailed)?
                    .decrypt_padded_vec::<Pkcs7>(ciphertext)
            }
            oid => {
                let (key_len, effective_bits) = if oid == oids::PBE_SHA1_RC2_128 {
                    (16, 128)
                } else {
                    (5, 40)
                };
                let key = derive(Purpose::Key, key_len);
                let cipher = rc2::Rc2::new_with_eff_key_len(&key, effective_bits);
                let iv = iv.as_slice().try_into().map_err(|_| Error::DecryptFailed)?;
                cbc::Decryptor::inner_iv_init(cipher, iv).decrypt_padded_vec::<Pkcs7>(ciphertext)
            }
        };
        plaintext
            .map(Zeroizing::new)
            .map_err(|_| Error::DecryptFailed)
    }
}
