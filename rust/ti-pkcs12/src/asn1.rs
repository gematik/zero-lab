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

//! The RFC 7292 structures, decoded with `der` in BER mode (P12-002). Owned types throughout:
//! indefinite lengths and constructed strings leave no contiguous value to borrow.

use der::asn1::{Any, ContextSpecific, ObjectIdentifier, OctetString, SetOfVec};
use der::{Decode, Encode, Reader, Sequence, Tag, TagNumber, Tagged, ValueOrd};
use spki::AlgorithmIdentifierOwned;

use crate::{Error, oids};

/// `PFX` (RFC 7292 §4).
#[derive(Clone, Debug)]
pub(crate) struct Pfx {
    pub version: u8,
    pub auth_safe: ContentInfo,
    pub mac_data: Option<MacData>,
}

impl<'a> Decode<'a> for Pfx {
    type Error = der::Error;

    fn decode<R: Reader<'a>>(reader: &mut R) -> der::Result<Self> {
        reader.sequence(|r| {
            Ok(Self {
                version: r.decode()?,
                auth_safe: r.decode()?,
                mac_data: r.decode()?,
            })
        })
    }
}

/// `ContentInfo` (RFC 2315 §7) with its content decoded by type. Hand-written: under
/// BER, [`Any`] reports a constructed OCTET STRING as primitive with its segment headers
/// as the value, which would change the octets the MAC covers (P12-011).
#[derive(Clone, Debug)]
pub(crate) struct ContentInfo {
    pub content_type: ObjectIdentifier,
    pub content: Content,
}

/// The content of a [`ContentInfo`].
#[derive(Clone, Debug)]
pub(crate) enum Content {
    /// `id-data`: the octets.
    Data(Vec<u8>),
    /// `id-encryptedData`.
    Encrypted(EncryptedData),
    /// No content, or a type PKCS#12 does not read.
    Other,
}

impl<'a> Decode<'a> for ContentInfo {
    type Error = der::Error;

    fn decode<R: Reader<'a>>(reader: &mut R) -> der::Result<Self> {
        reader.sequence(|r| {
            let content_type: ObjectIdentifier = r.decode()?;
            let content = if r.is_finished() {
                Content::Other
            } else {
                match content_type {
                    oids::DATA => ContextSpecific::<OctetString>::decode_explicit(r, TagNumber(0))?
                        .map_or(Content::Other, |c| {
                            Content::Data(c.value.into_bytes().into_vec())
                        }),
                    oids::ENCRYPTED_DATA => {
                        ContextSpecific::<EncryptedData>::decode_explicit(r, TagNumber(0))?
                            .map_or(Content::Other, |c| Content::Encrypted(c.value))
                    }
                    _ => {
                        r.decode::<Any>()?;
                        Content::Other
                    }
                }
            };
            Ok(Self {
                content_type,
                content,
            })
        })
    }
}

/// `MacData` (RFC 7292 §4).
#[derive(Clone, Debug, Sequence)]
pub(crate) struct MacData {
    pub mac: DigestInfo,
    pub mac_salt: OctetString,
    #[asn1(default = "one")]
    pub iterations: u32,
}

/// P12-013: absent iterations mean 1.
fn one() -> u32 {
    1
}

/// `DigestInfo` (RFC 8017 §9.2).
#[derive(Clone, Debug, Sequence)]
pub(crate) struct DigestInfo {
    pub algorithm: AlgorithmIdentifierOwned,
    pub digest: OctetString,
}

/// `SafeBag` (RFC 7292 §4.2).
#[derive(Clone, Debug, Sequence)]
pub(crate) struct SafeBag {
    pub id: ObjectIdentifier,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT")]
    pub value: Any,
    pub attributes: Option<SetOfVec<Attribute>>,
}

/// `PKCS12Attribute` (RFC 7292 §4.2).
#[derive(Clone, Debug, Sequence, ValueOrd)]
pub(crate) struct Attribute {
    pub attr_id: ObjectIdentifier,
    pub attr_values: SetOfVec<Any>,
}

/// `CertBag` (RFC 7292 §4.2.3).
#[derive(Clone, Debug, Sequence)]
pub(crate) struct CertBag {
    pub cert_id: ObjectIdentifier,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT")]
    pub cert_value: OctetString,
}

/// `EncryptedPrivateKeyInfo` (RFC 5208 §6).
#[derive(Clone, Debug, Sequence)]
pub(crate) struct EncryptedPrivateKeyInfo {
    pub encryption_algorithm: AlgorithmIdentifierOwned,
    pub encrypted_data: OctetString,
}

/// `pkcs-12PbeParams` (RFC 7292 Appendix C).
#[cfg(feature = "legacy")]
#[derive(Clone, Debug, Sequence)]
pub(crate) struct PbeParams {
    pub salt: OctetString,
    pub iterations: u32,
}

/// The `EncryptedData` of an encrypted safe (RFC 5652 §8): the algorithm and the
/// ciphertext. Hand-written, because BER writers may put the `[0] IMPLICIT OCTET
/// STRING` in its constructed form, which the derived decoder does not accept (P12-005).
#[derive(Clone, Debug)]
pub(crate) struct EncryptedData {
    pub algorithm: AlgorithmIdentifierOwned,
    pub ciphertext: Vec<u8>,
}

impl<'a> Decode<'a> for EncryptedData {
    type Error = der::Error;

    fn decode<R: Reader<'a>>(reader: &mut R) -> der::Result<Self> {
        reader.sequence(|outer| {
            let version: u8 = outer.decode()?;
            if version != 0 && version != 2 {
                return Err(der::Tag::Integer.value_error().into());
            }
            let parsed = outer.sequence(|info| {
                let _content_type: ObjectIdentifier = info.decode()?;
                let algorithm: AlgorithmIdentifierOwned = info.decode()?;
                let encrypted: Any = info.decode()?;
                Ok::<_, der::Error>(Self {
                    algorithm,
                    ciphertext: implicit_octets(&encrypted)?,
                })
            })?;
            // unprotectedAttrs [1] may follow; PKCS#12 uses none of them.
            while !outer.is_finished() {
                outer.decode::<Any>()?;
            }
            Ok(parsed)
        })
    }
}

/// Checks that `bytes` is exactly one DER `PrivateKeyInfo` (P12-041; `OneAsymmetricKey`,
/// RFC 5958 §2): version 0 or 1, an AlgorithmIdentifier, a non-empty privateKey,
/// attributes `[0]`, publicKey `[1]` only in version 1, nothing after it. A wrong password
/// on a file without MAC leaves valid padding in about 1 of 256 decryptions; the plaintext
/// is random then, and this check is what refuses it before it is returned as a key.
pub(crate) fn check_private_key_info(bytes: &[u8]) -> Result<(), Error> {
    PrivateKeyInfoShape::from_der(bytes)?;
    Ok(())
}

/// What [`check_private_key_info`] decodes: the structure only, the key stays in its octets.
struct PrivateKeyInfoShape;

impl<'a> Decode<'a> for PrivateKeyInfoShape {
    type Error = der::Error;

    fn decode<R: Reader<'a>>(reader: &mut R) -> der::Result<Self> {
        const ATTRIBUTES: Tag = Tag::ContextSpecific {
            constructed: true,
            number: TagNumber(0),
        };
        const PUBLIC_KEY: Tag = Tag::ContextSpecific {
            constructed: false,
            number: TagNumber(1),
        };
        reader.sequence(|r| {
            let version: u8 = r.decode()?;
            if version > 1 {
                return Err(Tag::Integer.value_error().into());
            }
            let _algorithm: AlgorithmIdentifierOwned = r.decode()?;
            let private_key: OctetString = r.decode()?;
            if private_key.as_bytes().is_empty() {
                return Err(Tag::OctetString.value_error().into());
            }
            if !r.is_finished() && Tag::peek(r)? == ATTRIBUTES {
                r.decode::<Any>()?;
            }
            if version == 1 && !r.is_finished() && Tag::peek(r)? == PUBLIC_KEY {
                r.decode::<Any>()?;
            }
            // Anything left is trailing data, which the sequence refuses.
            Ok(Self)
        })
    }
}

/// `T` from the element `value` holds, decoded again under BER: [`Any`]'s own
/// accessors assume DER for what is nested. Only for SEQUENCE values, which re-encode
/// losslessly (see [`ContentInfo`]).
pub(crate) fn reparse<T: for<'a> Decode<'a, Error = der::Error>>(value: &Any) -> Result<T, Error> {
    Ok(T::from_ber(&value.to_der()?)?)
}

/// The octets of the `[0] IMPLICIT OCTET STRING` `value`: the value itself when
/// primitive, the concatenated segments when constructed (BER). Context-specific tags
/// keep their constructed bit in [`Any`], unlike universal ones.
fn implicit_octets(value: &Any) -> der::Result<Vec<u8>> {
    let tag = value.tag();
    if tag.number() != TagNumber(0) {
        return Err(tag.value_error().into());
    }
    if !tag.is_constructed() {
        return Ok(value.value().to_vec());
    }
    let mut octets = Vec::new();
    let mut reader =
        der::SliceReader::new_with_encoding_rules(value.value(), der::EncodingRules::Ber)?;
    while !reader.is_finished() {
        octets.extend_from_slice(OctetString::decode(&mut reader)?.as_bytes());
    }
    Ok(octets)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    /// MacData without iterations: a SHA-256 DigestInfo of zeros and an 8-byte salt.
    const MAC_DATA_WITHOUT_ITERATIONS: &str = concat!(
        "303d",
        "3031300d0609608648016503040201050004200000000000000000000000000000000000000000000000000000000000000000",
        "04080707070707070707",
    );

    /// EncryptedData of `version`, PBES2 without parameters, three bytes of ciphertext.
    fn encrypted_data(version: u8) -> Vec<u8> {
        let mut der = bytes("30220201");
        der.push(version);
        der.extend(bytes(
            "301d06092a864886f70d010701300b06092a864886f70d01050d8003010203",
        ));
        der
    }

    /// P12-013: absent iterations mean 1.
    #[test]
    fn p12_013_absent_mac_iterations_mean_one() {
        let mac_data = MacData::from_der(&bytes(MAC_DATA_WITHOUT_ITERATIONS)).unwrap();
        assert_eq!(mac_data.iterations, 1);
    }

    /// RFC 5652 §8: EncryptedData is version 0, or 2 when it carries unprotected
    /// attributes; any other version is malformed.
    #[test]
    fn rfc5652_8_encrypted_data_is_version_0_or_2() {
        for version in [0, 2] {
            let parsed = EncryptedData::from_der(&encrypted_data(version)).unwrap();
            assert_eq!(parsed.algorithm.oid, oids::PBES2, "version {version}");
            assert_eq!(parsed.ciphertext, [1, 2, 3], "version {version}");
        }
        for version in [1, 3] {
            assert!(
                EncryptedData::from_der(&encrypted_data(version)).is_err(),
                "version {version}"
            );
        }
    }

    /// A `OneAsymmetricKey` (RFC 5958 §2) of `version` with Ed25519 as algorithm, the
    /// optional `parameters` and `private_key`, and `extra` after the private key.
    fn one_asymmetric_key(
        version: u8,
        parameters: &str,
        private_key: &[u8],
        extra: &str,
    ) -> Vec<u8> {
        let mut algorithm = bytes("06032b6570");
        algorithm.extend(bytes(parameters));
        let mut content = vec![
            0x02,
            0x01,
            version,
            0x30,
            u8::try_from(algorithm.len()).unwrap(),
        ];
        content.extend(algorithm);
        content.extend([0x04, u8::try_from(private_key.len()).unwrap()]);
        content.extend(private_key);
        content.extend(bytes(extra));
        let mut der = vec![0x30, u8::try_from(content.len()).unwrap()];
        der.extend(content);
        der
    }

    /// P12-041: a key is one DER `PrivateKeyInfo` as RFC 5958 allows it, and nothing else.
    #[test]
    fn p12_041_a_private_key_info_is_checked_strictly() {
        let seed = [0u8; 34];
        for (name, der) in [
            ("v1", one_asymmetric_key(0, "", &seed, "")),
            (
                "v1 with attributes",
                one_asymmetric_key(0, "", &seed, "a000"),
            ),
            (
                "v2 with public key",
                one_asymmetric_key(1, "", &seed, "81020001"),
            ),
            (
                "v2 with both",
                one_asymmetric_key(1, "", &seed, "a00081020001"),
            ),
            (
                "v2 without public key",
                one_asymmetric_key(1, "", &seed, ""),
            ),
            (
                "parameters of one element",
                one_asymmetric_key(0, "0500", &seed, ""),
            ),
        ] {
            assert!(check_private_key_info(&der).is_ok(), "{name}");
        }
        let mut trailing = one_asymmetric_key(0, "", &seed, "");
        trailing.push(0);
        for (name, der) in [
            ("empty", Vec::new()),
            ("trailing octet", trailing),
            ("version 2", one_asymmetric_key(2, "", &seed, "")),
            (
                "v1 with public key",
                one_asymmetric_key(0, "", &seed, "81020001"),
            ),
            (
                "public key before attributes",
                one_asymmetric_key(1, "", &seed, "81020001a000"),
            ),
            ("unknown field", one_asymmetric_key(1, "", &seed, "0500")),
            (
                "two parameters",
                one_asymmetric_key(0, "05000500", &seed, ""),
            ),
            ("empty private key", one_asymmetric_key(0, "", &[], "")),
            (
                "random octets",
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZ012345".to_vec(),
            ),
        ] {
            assert!(
                matches!(check_private_key_info(&der), Err(Error::Malformed { .. })),
                "{name}"
            );
        }
    }
}
