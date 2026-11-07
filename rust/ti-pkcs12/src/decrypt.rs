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

//! Decryption of shrouded key bags and encrypted safes: PBES2, and with the `legacy`
//! feature the PKCS#12 PBEs of RFC 7292 Appendix C (P12-033).

use spki::AlgorithmIdentifierOwned;
use zeroize::Zeroizing;

use crate::{Error, oids};

/// `ciphertext` decrypted under `algorithm` with `password`. PBES2 takes the password's
/// UTF-8 bytes (as OpenSSL does), the PKCS#12 PBEs its BMP form.
pub(crate) fn decrypt(
    algorithm: &AlgorithmIdentifierOwned,
    password: &str,
    ciphertext: &[u8],
    budget: &mut crate::Budget,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    match algorithm.oid {
        oids::PBES2 => crate::pbes2::decrypt(algorithm, password, ciphertext, budget),
        #[cfg(feature = "legacy")]
        oid if legacy::is_pkcs12_pbe(oid) => {
            legacy::decrypt(algorithm, password, ciphertext, budget)
        }
        oid => Err(Error::UnsupportedAlgorithm(oid)),
    }
}

/// The display name of an encryption algorithm, e.g. `PBES2 AES-256-CBC` or
/// `PKCS#12 3DES`.
pub(crate) fn name(algorithm: &AlgorithmIdentifierOwned) -> String {
    match algorithm.oid {
        oids::PBES2 => format!(
            "PBES2 {}",
            crate::pbes2::cipher_name(algorithm).unwrap_or_default()
        )
        .trim_end()
        .to_owned(),
        oid => pkcs12_pbe_name(oid).map_or_else(|| oid.to_string(), str::to_owned),
    }
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
        budget: &mut crate::Budget,
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        let parameters = algorithm
            .parameters
            .as_ref()
            .ok_or_else(|| Error::malformed("PBE parameters", "missing"))?;
        let params: PbeParams = reparse(parameters)?;
        // Key and IV are two derivations.
        budget.spend("PBE", params.iterations, 2)?;
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

// Every test here is of a legacy PBE.
#[cfg(all(test, feature = "legacy"))]
mod tests {
    use der::Any;
    use der::asn1::OctetString;

    use super::*;

    /// The decryption of one decode, with a budget of its own.
    fn decrypt(
        algorithm: &AlgorithmIdentifierOwned,
        password: &str,
        ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        super::decrypt(
            algorithm,
            password,
            ciphertext,
            &mut crate::Budget::default(),
        )
    }

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
    #[test]
    fn p12_036_pbe_iterations_above_the_limit_are_refused() {
        let err = decrypt(&pbe_algorithm(u32::MAX), "pw", &[0; 16]).unwrap_err();
        assert!(
            matches!(err, Error::LimitExceeded { what: "PBE", .. }),
            "{err}"
        );
    }

    /// P12-036: an explicit count of 0 is malformed, not silently 1.
    #[test]
    fn p12_036_zero_iterations_are_malformed() {
        let err = decrypt(&pbe_algorithm(0), "pw", &[0; 16]).unwrap_err();
        assert!(matches!(err, Error::Malformed { .. }), "{err}");
    }

    /// P12-033: RC4, with parameters a PKCS#12 PBE would accept, is unsupported rather
    /// than decrypted under another PBE.
    #[test]
    fn p12_033_rc4_is_unsupported() {
        let rc4 = der::asn1::ObjectIdentifier::new_unwrap("1.2.840.113549.1.12.1.1");
        let algorithm = AlgorithmIdentifierOwned {
            oid: rc4,
            ..pbe_algorithm(1)
        };
        let err = decrypt(&algorithm, "pw", &[0; 16]).unwrap_err();
        assert!(
            matches!(err, Error::UnsupportedAlgorithm(oid) if oid == rc4),
            "{err}"
        );
    }

    /// What a file is encrypted with is reported by name: an API property, no rule.
    #[test]
    fn pkcs12_pbes_are_reported_by_name() {
        for (oid, expected) in [
            (oids::PBE_SHA1_3DES, "PKCS#12 3DES"),
            (oids::PBE_SHA1_2DES, "PKCS#12 2-key 3DES"),
            (oids::PBE_SHA1_RC2_128, "PKCS#12 RC2-128"),
            (oids::PBE_SHA1_RC2_40, "PKCS#12 RC2-40"),
        ] {
            assert_eq!(
                name(&AlgorithmIdentifierOwned {
                    oid,
                    parameters: None
                }),
                expected
            );
        }
    }
}
