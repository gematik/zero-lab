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

//! The password integrity mode (RFC 7292 §5.1): an HMAC over the auth-safe octets with
//! a key from the PKCS#12 KDF.

use der::asn1::ObjectIdentifier;
use hmac::{KeyInit, Mac, SimpleHmac};
use sha1::Sha1;
use sha2::digest::block_api::BlockSizeUser;
use sha2::{Digest, Sha224, Sha256, Sha384, Sha512};

use crate::asn1::MacData;
use crate::kdf::{self, Purpose};
use crate::{Error, oids};

/// Checks `mac_data` over `content` with the KDF-ready `password`.
pub(crate) fn verify(
    mac_data: &MacData,
    password: &[u8],
    content: &[u8],
    budget: &mut crate::Budget,
) -> Result<(), Error> {
    let oid = mac_data.mac.algorithm.oid;
    // P12-012: the HMAC OIDs stand for their digests; some producers, go/pkcs12 up to
    // v0.99.3 among them, wrote them in place of the digest OIDs.
    let check = match oid {
        oids::SHA1 | oids::HMAC_WITH_SHA1 => check::<Sha1>,
        oids::SHA224 | oids::HMAC_WITH_SHA224 => check::<Sha224>,
        oids::SHA256 | oids::HMAC_WITH_SHA256 => check::<Sha256>,
        oids::SHA384 | oids::HMAC_WITH_SHA384 => check::<Sha384>,
        oids::SHA512 | oids::HMAC_WITH_SHA512 => check::<Sha512>,
        // P12-012: any other MAC algorithm, PBMAC1 included, is unsupported.
        _ => return Err(Error::UnsupportedAlgorithm(oid)),
    };
    budget.spend("MAC", mac_data.iterations, 1)?;
    if check(
        password,
        mac_data.mac_salt.as_bytes(),
        mac_data.iterations,
        content,
        mac_data.mac.digest.as_bytes(),
    ) {
        Ok(())
    } else {
        Err(Error::MacMismatch)
    }
}

/// The digest name of a MAC algorithm, for display.
pub(crate) fn name(oid: ObjectIdentifier) -> Option<&'static str> {
    Some(match oid {
        oids::SHA1 | oids::HMAC_WITH_SHA1 => "SHA-1",
        oids::SHA224 | oids::HMAC_WITH_SHA224 => "SHA-224",
        oids::SHA256 | oids::HMAC_WITH_SHA256 => "SHA-256",
        oids::SHA384 | oids::HMAC_WITH_SHA384 => "SHA-384",
        oids::SHA512 | oids::HMAC_WITH_SHA512 => "SHA-512",
        _ => return None,
    })
}

fn check<D: Digest + BlockSizeUser + Clone>(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    content: &[u8],
    expected: &[u8],
) -> bool {
    // P12-013: the MAC key is as long as the digest (RFC 7292 B.4).
    let key = kdf::derive::<D>(
        password,
        salt,
        iterations,
        Purpose::Mac,
        <D as Digest>::output_size(),
    );
    let Ok(mut mac) = <SimpleHmac<D> as KeyInit>::new_from_slice(&key) else {
        return false;
    };
    mac.update(content);
    // P12-014: `verify_slice` compares in constant time.
    mac.verify_slice(expected).is_ok()
}

#[cfg(test)]
mod tests {
    use der::asn1::OctetString;
    use spki::AlgorithmIdentifierOwned;

    use super::*;
    use crate::asn1::DigestInfo;

    /// The MAC check of one decode, with a budget of its own.
    fn verify(mac_data: &MacData, password: &[u8], content: &[u8]) -> Result<(), Error> {
        super::verify(mac_data, password, content, &mut crate::Budget::default())
    }

    /// P12-036: a crafted MAC count fails at once instead of costing billions of hashes
    /// (the corpus case `mac-iterations-limit`).
    #[test]
    fn p12_036_mac_iterations_above_the_limit_are_refused() {
        let mac_data = MacData {
            mac: DigestInfo {
                algorithm: AlgorithmIdentifierOwned {
                    oid: oids::SHA256,
                    parameters: None,
                },
                digest: OctetString::new(vec![0; 32]).unwrap(),
            },
            mac_salt: OctetString::new(vec![7; 8]).unwrap(),
            iterations: 2_147_483_647,
        };
        let err = verify(&mac_data, b"\0t\0e\0s\0t\0\0", b"content").unwrap_err();
        assert!(
            matches!(
                err,
                Error::LimitExceeded {
                    what: "MAC",
                    iterations: 2_147_483_647
                }
            ),
            "{err}"
        );
    }

    /// The MAC of `content` under digest `D`, as RFC 7292 appendix B and §4 define it,
    /// in a [`MacData`] naming `oid`.
    fn mac_data<D: Digest + BlockSizeUser + Clone>(
        oid: ObjectIdentifier,
        password: &[u8],
        content: &[u8],
    ) -> MacData {
        let salt = [7; 8];
        let key = kdf::derive::<D>(
            password,
            &salt,
            1,
            Purpose::Mac,
            <D as Digest>::output_size(),
        );
        let mut mac = <SimpleHmac<D> as KeyInit>::new_from_slice(&key).unwrap();
        mac.update(content);
        MacData {
            mac: DigestInfo {
                algorithm: AlgorithmIdentifierOwned {
                    oid,
                    parameters: None,
                },
                digest: OctetString::new(mac.finalize().into_bytes().to_vec()).unwrap(),
            },
            mac_salt: OctetString::new(salt.to_vec()).unwrap(),
            iterations: 1,
        }
    }

    /// P12-012: every listed MAC digest verifies, each with its own hash, and so does
    /// each HMAC OID in place of its digest.
    #[test]
    fn p12_012_every_listed_mac_digest_verifies() {
        let password = b"\0t\0e\0s\0t\0\0";
        let content = b"auth safe";
        for (name, mac_data) in [
            ("SHA-1", mac_data::<Sha1>(oids::SHA1, password, content)),
            (
                "SHA-224",
                mac_data::<Sha224>(oids::SHA224, password, content),
            ),
            (
                "SHA-256",
                mac_data::<Sha256>(oids::SHA256, password, content),
            ),
            (
                "SHA-384",
                mac_data::<Sha384>(oids::SHA384, password, content),
            ),
            (
                "SHA-512",
                mac_data::<Sha512>(oids::SHA512, password, content),
            ),
            (
                "hmacWithSHA1",
                mac_data::<Sha1>(oids::HMAC_WITH_SHA1, password, content),
            ),
            (
                "hmacWithSHA224",
                mac_data::<Sha224>(oids::HMAC_WITH_SHA224, password, content),
            ),
            (
                "hmacWithSHA256",
                mac_data::<Sha256>(oids::HMAC_WITH_SHA256, password, content),
            ),
            (
                "hmacWithSHA384",
                mac_data::<Sha384>(oids::HMAC_WITH_SHA384, password, content),
            ),
            (
                "hmacWithSHA512",
                mac_data::<Sha512>(oids::HMAC_WITH_SHA512, password, content),
            ),
        ] {
            assert!(verify(&mac_data, password, content).is_ok(), "{name}");
            assert!(
                matches!(
                    verify(&mac_data, password, b"altered"),
                    Err(Error::MacMismatch)
                ),
                "{name}"
            );
        }
    }

    /// What a file's MAC uses is reported by name: an API property, no rule.
    #[test]
    fn mac_digests_are_reported_by_name() {
        for (oid, expected) in [
            (oids::SHA1, "SHA-1"),
            (oids::SHA224, "SHA-224"),
            (oids::SHA256, "SHA-256"),
            (oids::SHA384, "SHA-384"),
            (oids::SHA512, "SHA-512"),
            (oids::HMAC_WITH_SHA1, "SHA-1"),
            (oids::HMAC_WITH_SHA224, "SHA-224"),
            (oids::HMAC_WITH_SHA256, "SHA-256"),
            (oids::HMAC_WITH_SHA384, "SHA-384"),
            (oids::HMAC_WITH_SHA512, "SHA-512"),
        ] {
            assert_eq!(name(oid), Some(expected));
        }
        assert_eq!(name(oids::PBKDF2), None);
    }
}
