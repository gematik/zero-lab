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
    let pkcs5::EncryptionScheme::Pbes2(params) = &scheme else {
        return Err(Error::UnsupportedAlgorithm(algorithm.oid));
    };
    match &params.kdf {
        pkcs5::pbes2::Kdf::Pbkdf2(pbkdf2) => {
            crate::check_iterations("PBKDF2", pbkdf2.iteration_count)?;
        }
        // PBES2 means PBKDF2 here (P12-030): scrypt would let the file choose its
        // memory cost, and no PKCS#12 producer writes it.
        other => return Err(Error::UnsupportedAlgorithm(other.oid())),
    }
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
        crate::check_iterations("PBE", params.iterations)?;
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

#[cfg(test)]
mod tests {
    use der::Any;
    use der::asn1::OctetString;
    use pkcs5::pbes2::{self, Kdf, ScryptParams};

    use super::*;
    use crate::MAX_ITERATIONS;

    fn pbes2_algorithm(params: &pbes2::Parameters) -> AlgorithmIdentifierOwned {
        AlgorithmIdentifierOwned {
            oid: oids::PBES2,
            parameters: Some(Any::encode_from(params).unwrap()),
        }
    }

    /// P12-036: a PBKDF2 count above the limit fails before any key is derived.
    #[test]
    fn p12_036_pbkdf2_iterations_above_the_limit_are_refused() {
        // pkcs5 refuses such a count when constructing, but not when decoding: a crafted
        // file gets it through, which is what this check is for.
        let mut params =
            pbes2::Parameters::generate_pbkdf2_sha256_aes256cbc(2048, &[7; 16], [0; 16]).unwrap();
        let Kdf::Pbkdf2(pbkdf2) = &mut params.kdf else {
            unreachable!()
        };
        pbkdf2.iteration_count = u32::MAX;
        let err = decrypt(&pbes2_algorithm(&params), "pw", &[0; 16]).unwrap_err();
        assert!(
            matches!(
                err,
                Error::LimitExceeded {
                    what: "PBKDF2",
                    iterations: u32::MAX
                }
            ),
            "{err}"
        );
    }

    /// P12-036: the limit itself is allowed, one more is not.
    #[test]
    fn p12_036_iterations_at_the_limit_pass_the_check() {
        assert!(crate::check_iterations("PBKDF2", MAX_ITERATIONS).is_ok());
        assert!(matches!(
            crate::check_iterations("PBKDF2", MAX_ITERATIONS + 1),
            Err(Error::LimitExceeded { .. })
        ));
    }

    /// P12-030: PBES2 means PBKDF2; scrypt, whose memory cost the file would choose, is
    /// unsupported.
    #[test]
    fn p12_030_scrypt_is_unsupported() {
        let params = pbes2::Parameters {
            kdf: Kdf::Scrypt(ScryptParams {
                salt: (&[7; 16][..]).try_into().unwrap(),
                cost_parameter: 1 << 30,
                block_size: 8,
                parallelization: 1,
                key_length: None,
            }),
            encryption: pbes2::EncryptionScheme::Aes256Cbc { iv: [0; 16] },
        };
        let err = decrypt(&pbes2_algorithm(&params), "pw", &[0; 16]).unwrap_err();
        assert!(
            matches!(err, Error::UnsupportedAlgorithm(oid) if oid == pbes2::SCRYPT_OID),
            "{err}"
        );
    }

    #[cfg(feature = "legacy")]
    fn pbe_algorithm(iterations: u32) -> AlgorithmIdentifierOwned {
        let params = crate::asn1::PbeParams {
            salt: OctetString::new(vec![7; 8]).unwrap(),
            iterations,
        };
        AlgorithmIdentifierOwned {
            oid: oids::PBE_SHA1_3DES,
            parameters: Some(Any::encode_from(&params).unwrap()),
        }
    }

    /// P12-036: the PKCS#12 KDF of the legacy PBEs is bounded like PBKDF2.
    #[cfg(feature = "legacy")]
    #[test]
    fn p12_036_pbe_iterations_above_the_limit_are_refused() {
        let err = decrypt(&pbe_algorithm(u32::MAX), "pw", &[0; 16]).unwrap_err();
        assert!(
            matches!(err, Error::LimitExceeded { what: "PBE", .. }),
            "{err}"
        );
    }

    /// P12-036: an explicit count of 0 is malformed, not silently 1.
    #[cfg(feature = "legacy")]
    #[test]
    fn p12_036_zero_iterations_are_malformed() {
        let err = decrypt(&pbe_algorithm(0), "pw", &[0; 16]).unwrap_err();
        assert!(matches!(err, Error::Malformed { .. }), "{err}");
    }
}
