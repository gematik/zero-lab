//! The RFC 7292 structures, decoded with `der` in BER mode. Owned types throughout:
//! indefinite lengths and constructed strings leave no contiguous value to borrow.

use der::asn1::{Any, ContextSpecific, ObjectIdentifier, OctetString, SetOfVec};
use der::{Decode, Encode, Reader, Sequence, TagNumber, Tagged, ValueOrd};
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
/// as the value, which would change the octets the MAC covers.
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
/// STRING` in its constructed form, which the derived decoder does not accept.
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
