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

//! PBES2 (RFC 8018 §6.2) as PKCS#12 uses it: PBKDF2 with HMAC, AES-CBC and, with the
//! `legacy` feature, DES-EDE3-CBC (P12-030 – P12-034). A file names nothing else that
//! ends up running: scrypt, whose memory cost the file would choose, is unsupported.

use aes::{Aes128, Aes192, Aes256};
use cbc::cipher::block_padding::Pkcs7;
use cbc::cipher::{BlockCipherDecrypt, BlockModeDecrypt, KeyIvInit};
use der::Sequence;
use der::asn1::{ObjectIdentifier, OctetString};
use sha2::{Sha224, Sha256, Sha384, Sha512};
use spki::AlgorithmIdentifierOwned;
use zeroize::Zeroizing;

use crate::asn1::reparse;
use crate::{Error, oids};

/// `PBES2-params`.
#[derive(Clone, Debug, Sequence)]
struct Params {
    kdf: AlgorithmIdentifierOwned,
    cipher: AlgorithmIdentifierOwned,
}

/// `PBKDF2-params`; a salt from `otherSource` does not decode. `prf` absent means
/// hmacWithSHA1 (P12-030).
#[derive(Clone, Debug, Sequence)]
struct Pbkdf2Params {
    salt: OctetString,
    iterations: u32,
    key_length: Option<u32>,
    prf: Option<AlgorithmIdentifierOwned>,
}

#[derive(Clone, Copy)]
enum Prf {
    #[cfg(feature = "legacy")]
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
}

impl Prf {
    /// P12-030: an unknown PRF is unsupported, never a fallback.
    fn of(prf: Option<&AlgorithmIdentifierOwned>) -> Result<Self, Error> {
        let Some(prf) = prf else {
            return Self::of_oid(oids::HMAC_WITH_SHA1);
        };
        if prf.parameters.as_ref().is_some_and(|p| !p.is_null()) {
            return Err(Error::malformed("PBKDF2 PRF", "parameters other than NULL"));
        }
        Self::of_oid(prf.oid)
    }

    fn of_oid(oid: ObjectIdentifier) -> Result<Self, Error> {
        match oid {
            #[cfg(feature = "legacy")]
            oids::HMAC_WITH_SHA1 => Ok(Prf::Sha1),
            oids::HMAC_WITH_SHA224 => Ok(Prf::Sha224),
            oids::HMAC_WITH_SHA256 => Ok(Prf::Sha256),
            oids::HMAC_WITH_SHA384 => Ok(Prf::Sha384),
            oids::HMAC_WITH_SHA512 => Ok(Prf::Sha512),
            other => Err(Error::UnsupportedAlgorithm(other)),
        }
    }

    fn derive(self, password: &[u8], salt: &[u8], iterations: u32, key: &mut [u8]) {
        match self {
            #[cfg(feature = "legacy")]
            Prf::Sha1 => pbkdf2::pbkdf2_hmac::<sha1::Sha1>(password, salt, iterations, key),
            Prf::Sha224 => pbkdf2::pbkdf2_hmac::<Sha224>(password, salt, iterations, key),
            Prf::Sha256 => pbkdf2::pbkdf2_hmac::<Sha256>(password, salt, iterations, key),
            Prf::Sha384 => pbkdf2::pbkdf2_hmac::<Sha384>(password, salt, iterations, key),
            Prf::Sha512 => pbkdf2::pbkdf2_hmac::<Sha512>(password, salt, iterations, key),
        }
    }
}

#[derive(Clone, Copy)]
enum Cipher {
    Aes128,
    Aes192,
    Aes256,
    #[cfg(feature = "legacy")]
    DesEde3,
}

impl Cipher {
    fn of(oid: ObjectIdentifier) -> Result<Self, Error> {
        match oid {
            oids::AES_128_CBC => Ok(Cipher::Aes128),
            oids::AES_192_CBC => Ok(Cipher::Aes192),
            oids::AES_256_CBC => Ok(Cipher::Aes256),
            #[cfg(feature = "legacy")]
            oids::DES_EDE3_CBC => Ok(Cipher::DesEde3),
            other => Err(Error::UnsupportedAlgorithm(other)),
        }
    }

    const fn key_size(self) -> usize {
        match self {
            Cipher::Aes128 => 16,
            Cipher::Aes192 => 24,
            Cipher::Aes256 => 32,
            #[cfg(feature = "legacy")]
            Cipher::DesEde3 => 24,
        }
    }

    fn decrypt(self, key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        match self {
            Cipher::Aes128 => cbc_decrypt::<Aes128>(key, iv, ciphertext),
            Cipher::Aes192 => cbc_decrypt::<Aes192>(key, iv, ciphertext),
            Cipher::Aes256 => cbc_decrypt::<Aes256>(key, iv, ciphertext),
            #[cfg(feature = "legacy")]
            Cipher::DesEde3 => cbc_decrypt::<des::TdesEde3>(key, iv, ciphertext),
        }
    }
}

/// P12-034: a key or IV of the wrong size and every padding failure are one error.
fn cbc_decrypt<C>(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Error>
where
    C: BlockCipherDecrypt,
    cbc::Decryptor<C>: KeyIvInit + BlockModeDecrypt,
{
    cbc::Decryptor::<C>::new_from_slices(key, iv)
        .map_err(|_| Error::DecryptFailed)?
        .decrypt_padded_vec::<Pkcs7>(ciphertext)
        .map_err(|_| Error::DecryptFailed)
}

fn params(algorithm: &AlgorithmIdentifierOwned) -> Result<Params, Error> {
    let parameters = algorithm
        .parameters
        .as_ref()
        .ok_or_else(|| Error::malformed("PBES2 parameters", "missing"))?;
    reparse(parameters)
}

/// `ciphertext` decrypted under the PBES2 `algorithm`, with the checks in the order of
/// the specification's decrypt algorithm: nothing is derived before they all passed.
pub(crate) fn decrypt(
    algorithm: &AlgorithmIdentifierOwned,
    password: &str,
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let params = params(algorithm)?;
    if params.kdf.oid != oids::PBKDF2 {
        return Err(Error::UnsupportedAlgorithm(params.kdf.oid));
    }
    let kdf_parameters = params
        .kdf
        .parameters
        .as_ref()
        .ok_or_else(|| Error::malformed("PBKDF2 parameters", "missing"))?;
    let kdf: Pbkdf2Params = reparse(kdf_parameters)?;
    let prf = Prf::of(kdf.prf.as_ref())?;
    let cipher = Cipher::of(params.cipher.oid)?;
    if kdf
        .key_length
        .is_some_and(|len| usize::try_from(len) != Ok(cipher.key_size()))
    {
        return Err(Error::malformed(
            "PBKDF2 keyLength",
            "differs from the key size of the cipher",
        ));
    }
    crate::check_iterations("PBKDF2", kdf.iterations)?;
    let iv_parameter = params
        .cipher
        .parameters
        .as_ref()
        .ok_or_else(|| Error::malformed("PBES2 IV", "missing"))?;
    let iv: OctetString = reparse(iv_parameter)?;
    let mut key = Zeroizing::new(vec![0u8; cipher.key_size()]);
    prf.derive(
        password.as_bytes(),
        kdf.salt.as_bytes(),
        kdf.iterations,
        &mut key,
    );
    cipher
        .decrypt(&key, iv.as_bytes(), ciphertext)
        .map(Zeroizing::new)
}

/// The name of the cipher of the PBES2 `algorithm`, its OID if unknown, `None` if the
/// parameters do not decode.
pub(crate) fn cipher_name(algorithm: &AlgorithmIdentifierOwned) -> Option<String> {
    let oid = params(algorithm).ok()?.cipher.oid;
    Some(
        match oid {
            oids::AES_128_CBC => "AES-128-CBC",
            oids::AES_192_CBC => "AES-192-CBC",
            oids::AES_256_CBC => "AES-256-CBC",
            oids::DES_EDE3_CBC => "DES-EDE3-CBC",
            other => return Some(other.to_string()),
        }
        .to_owned(),
    )
}

/// `plaintext` encrypted with PBKDF2-HMAC-SHA-256 and AES-256-CBC, and the algorithm to
/// name in the file.
#[cfg(feature = "encode")]
pub(crate) fn encrypt(
    password: &str,
    plaintext: &[u8],
    salt: &[u8],
    iv: [u8; 16],
    iterations: u32,
) -> Result<(AlgorithmIdentifierOwned, Vec<u8>), Error> {
    use cbc::cipher::BlockModeEncrypt;
    use der::asn1::{Any, Null};

    let mut key = Zeroizing::new([0u8; 32]);
    Prf::Sha256.derive(password.as_bytes(), salt, iterations, key.as_mut_slice());
    let ciphertext = cbc::Encryptor::<Aes256>::new_from_slices(key.as_slice(), &iv)
        .map_err(|e| Error::malformed("PBES2 encryption", e.to_string()))?
        .encrypt_padded_vec::<Pkcs7>(plaintext);
    let kdf = Pbkdf2Params {
        salt: OctetString::new(salt)?,
        iterations,
        key_length: None,
        prf: Some(AlgorithmIdentifierOwned {
            oid: oids::HMAC_WITH_SHA256,
            parameters: Some(Any::encode_from(&Null)?),
        }),
    };
    let params = Params {
        kdf: AlgorithmIdentifierOwned {
            oid: oids::PBKDF2,
            parameters: Some(Any::encode_from(&kdf)?),
        },
        cipher: AlgorithmIdentifierOwned {
            oid: oids::AES_256_CBC,
            parameters: Some(Any::encode_from(&OctetString::new(iv)?)?),
        },
    };
    let algorithm = AlgorithmIdentifierOwned {
        oid: oids::PBES2,
        parameters: Some(Any::encode_from(&params)?),
    };
    Ok((algorithm, ciphertext))
}

#[cfg(test)]
mod tests {
    use der::asn1::{Any, Null};

    use super::*;
    use crate::MAX_ITERATIONS;

    const SCRYPT: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.11591.4.11");

    fn algorithm(
        kdf: AlgorithmIdentifierOwned,
        cipher: ObjectIdentifier,
        iv: &[u8],
    ) -> AlgorithmIdentifierOwned {
        let params = Params {
            kdf,
            cipher: AlgorithmIdentifierOwned {
                oid: cipher,
                parameters: Some(Any::encode_from(&OctetString::new(iv).unwrap()).unwrap()),
            },
        };
        AlgorithmIdentifierOwned {
            oid: oids::PBES2,
            parameters: Some(Any::encode_from(&params).unwrap()),
        }
    }

    fn pbkdf2(
        iterations: u32,
        key_length: Option<u32>,
        prf: Option<ObjectIdentifier>,
    ) -> AlgorithmIdentifierOwned {
        let params = Pbkdf2Params {
            salt: OctetString::new(vec![7; 16]).unwrap(),
            iterations,
            key_length,
            prf: prf.map(|oid| AlgorithmIdentifierOwned {
                oid,
                parameters: Some(Any::encode_from(&Null).unwrap()),
            }),
        };
        AlgorithmIdentifierOwned {
            oid: oids::PBKDF2,
            parameters: Some(Any::encode_from(&params).unwrap()),
        }
    }

    fn sha256(iterations: u32) -> AlgorithmIdentifierOwned {
        pbkdf2(iterations, None, Some(oids::HMAC_WITH_SHA256))
    }

    /// PBKDF2-HMAC-SHA-256, 1 iteration, salt 16 × 0x07, password "pw", AES-128-CBC, IV 16
    /// × 0x00, plaintext "TEST-ONLY", from OpenSSL 4.1:
    /// `openssl kdf -keylen 16 -kdfopt digest:SHA256 -kdfopt pass:pw -kdfopt hexsalt:0707…07
    /// -kdfopt iter:1 PBKDF2`, then `openssl enc -aes-128-cbc -K … -iv 00…00`.
    const OPENSSL_CIPHERTEXT: &str = "02d4f1db123cc525bc1e8213e6c06238";

    fn unhex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    /// P12-030, P12-031, P12-034: an OpenSSL ciphertext decrypts.
    #[test]
    fn p12_030_pbkdf2_and_aes_decrypt_what_openssl_wrote() {
        let plain = decrypt(
            &algorithm(sha256(1), oids::AES_128_CBC, &[0; 16]),
            "pw",
            &unhex(OPENSSL_CIPHERTEXT),
        )
        .unwrap();
        assert_eq!(plain.as_slice(), b"TEST-ONLY");
    }

    /// P12-030: scrypt, whose memory cost the file would choose, is unsupported.
    #[test]
    fn p12_030_scrypt_is_unsupported() {
        let kdf = AlgorithmIdentifierOwned {
            oid: SCRYPT,
            parameters: None,
        };
        let err =
            decrypt(&algorithm(kdf, oids::AES_256_CBC, &[0; 16]), "pw", &[0; 16]).unwrap_err();
        assert!(
            matches!(err, Error::UnsupportedAlgorithm(oid) if oid == SCRYPT),
            "{err}"
        );
    }

    /// P12-030: an unknown PRF is unsupported, never a fallback.
    #[test]
    fn p12_030_an_unknown_prf_is_unsupported() {
        let unknown = ObjectIdentifier::new_unwrap("1.2.3.4");
        let kdf = pbkdf2(1, None, Some(unknown));
        let err =
            decrypt(&algorithm(kdf, oids::AES_256_CBC, &[0; 16]), "pw", &[0; 16]).unwrap_err();
        assert!(
            matches!(err, Error::UnsupportedAlgorithm(oid) if oid == unknown),
            "{err}"
        );
    }

    /// P12-030: without a PRF, PBKDF2 uses hmacWithSHA1, which only `legacy` has.
    #[test]
    fn p12_030_an_absent_prf_means_sha1() {
        let result = decrypt(
            &algorithm(pbkdf2(1, None, None), oids::AES_256_CBC, &[0; 16]),
            "pw",
            &[0; 16],
        );
        #[cfg(feature = "legacy")]
        assert!(matches!(result, Err(Error::DecryptFailed)));
        #[cfg(not(feature = "legacy"))]
        assert!(
            matches!(result, Err(Error::UnsupportedAlgorithm(oid)) if oid == oids::HMAC_WITH_SHA1)
        );
    }

    /// P12-031: an unknown cipher is unsupported.
    #[test]
    fn p12_031_an_unknown_cipher_is_unsupported() {
        let unknown = ObjectIdentifier::new_unwrap("1.2.3.4");
        let err = decrypt(&algorithm(sha256(1), unknown, &[0; 16]), "pw", &[0; 16]).unwrap_err();
        assert!(
            matches!(err, Error::UnsupportedAlgorithm(oid) if oid == unknown),
            "{err}"
        );
    }

    /// P12-032: a keyLength other than the cipher's key size is malformed.
    #[test]
    fn p12_032_a_key_length_must_match_the_cipher() {
        let good = pbkdf2(1, Some(32), Some(oids::HMAC_WITH_SHA256));
        let result = decrypt(
            &algorithm(good, oids::AES_256_CBC, &[0; 16]),
            "pw",
            &[0; 16],
        );
        assert!(matches!(result, Err(Error::DecryptFailed)));
        let bad = pbkdf2(1, Some(16), Some(oids::HMAC_WITH_SHA256));
        let err =
            decrypt(&algorithm(bad, oids::AES_256_CBC, &[0; 16]), "pw", &[0; 16]).unwrap_err();
        assert!(matches!(err, Error::Malformed { .. }), "{err}");
    }

    /// P12-034: a wrong IV size and ciphertext of a wrong length fail decryption.
    #[test]
    fn p12_034_a_wrong_iv_or_ciphertext_length_fails_decryption() {
        for (iv, ciphertext) in [
            (&[0u8; 8][..], &[0u8; 16][..]),
            (&[0; 16], &[]),
            (&[0; 16], &[0; 15]),
        ] {
            let result = decrypt(
                &algorithm(sha256(1), oids::AES_256_CBC, iv),
                "pw",
                ciphertext,
            );
            assert!(
                matches!(result, Err(Error::DecryptFailed)),
                "{iv:?} {ciphertext:?}"
            );
        }
    }

    /// P12-036: a PBKDF2 count above the limit fails before any key is derived, and 0 is
    /// malformed.
    #[test]
    fn p12_036_pbkdf2_iterations_are_bounded() {
        let run = |iterations| {
            decrypt(
                &algorithm(sha256(iterations), oids::AES_256_CBC, &[0; 16]),
                "pw",
                &[0; 16],
            )
        };
        assert!(matches!(
            run(u32::MAX),
            Err(Error::LimitExceeded {
                what: "PBKDF2",
                iterations: u32::MAX
            })
        ));
        assert!(matches!(
            run(MAX_ITERATIONS + 1),
            Err(Error::LimitExceeded { .. })
        ));
        assert!(matches!(run(0), Err(Error::Malformed { .. })));
    }

    /// What `encrypt` writes, `decrypt` reads.
    #[cfg(feature = "encode")]
    #[test]
    fn encrypt_round_trips() {
        let (algorithm, ciphertext) = encrypt("pw", b"TEST-ONLY", &[7; 16], [9; 16], 2).unwrap();
        let plain = decrypt(&algorithm, "pw", &ciphertext).unwrap();
        assert_eq!(plain.as_slice(), b"TEST-ONLY");
    }
}
