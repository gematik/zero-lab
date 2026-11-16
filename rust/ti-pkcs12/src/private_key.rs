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

//! The P12-041 check of a PrivateKeyInfo, and the join of the segmented publicKey a keyBag
//! may carry (P12-002). Read by hand over the DER octets rather than with `der` and
//! `spki`: the rule bounds OIDs and tag numbers on its own terms (const-oid refuses OIDs it
//! could hold, such as 2.1967, and reads an arc of 2^32), and go/pkcs12 holds the same
//! bounds in its internal/syntax.

use zeroize::Zeroizing;

use crate::Error;
use crate::ber::element;

/// The nesting the check walks, the PrivateKeyInfo at depth 0 (P12-004).
const MAX_DEPTH: usize = 64;
/// The content octets of the algorithm OID (P12-041).
const MAX_OID_LENGTH: usize = 39;

const UNIVERSAL: u8 = 0x00;
const CONTEXT: u8 = 0x80;

const TAG_INTEGER: u32 = 2;
const TAG_BIT_STRING: u32 = 3;
const TAG_OCTET_STRING: u32 = 4;
const TAG_OID: u32 = 6;
const TAG_SEQUENCE: u32 = 16;

fn malformed(reason: &str) -> Error {
    Error::malformed("PrivateKeyInfo", reason)
}

/// One element read in DER form.
struct Element<'a> {
    class: u8,
    constructed: bool,
    tag: u32,
    content: &'a [u8],
}

impl Element<'_> {
    fn is(&self, class: u8, constructed: bool, tag: u32) -> bool {
        self.class == class && self.constructed == constructed && self.tag == tag
    }
}

/// The element at the start of `bytes` in DER form (X.690 §10) and the bytes after it: the
/// low tag form for numbers up to 30, a minimal high form above with at most 32 bits, a
/// definite length in the fewest octets.
fn read(bytes: &[u8]) -> Option<(Element<'_>, &[u8])> {
    let (&first, mut rest) = bytes.split_first()?;
    let mut tag = u32::from(first & 0x1f);
    if tag == 0x1f {
        tag = 0;
        let mut leading = true;
        loop {
            let (&b, next) = rest.split_first()?;
            if (leading && b == 0x80) || tag > u32::MAX >> 7 {
                return None;
            }
            leading = false;
            rest = next;
            tag = tag << 7 | u32::from(b & 0x7f);
            if b & 0x80 == 0 {
                break;
            }
        }
        if tag < 0x1f {
            return None;
        }
    }
    let (&len, mut rest) = rest.split_first()?;
    let length = match len {
        0..=0x7f => usize::from(len),
        0x81..=0x84 => {
            let (octets, next) = rest.split_at_checked(usize::from(len & 0x7f))?;
            if octets.first() == Some(&0) {
                return None;
            }
            rest = next;
            let value = octets.iter().fold(0u64, |acc, &b| acc << 8 | u64::from(b));
            if value < 0x80 {
                return None;
            }
            usize::try_from(value).ok()?
        }
        _ => return None,
    };
    let (content, rest) = rest.split_at_checked(length)?;
    let element = Element {
        class: first & 0xc0,
        constructed: first & 0x20 != 0,
        tag,
        content,
    };
    Some((element, rest))
}

/// Whether a universal tag is one this specification reads, in the form DER gives it:
/// SEQUENCE and SET constructed, the others primitive (X.690 §10.2 for strings).
fn universal_form(tag: u32, constructed: bool) -> bool {
    match tag {
        16 | 17 => constructed,
        1..=6 | 9 | 10 | 12 | 13 | 18..=24 | 26 | 27 | 30 => !constructed,
        _ => false,
    }
}

/// Whether `content` is a run of DER elements, each checked as at `depth`.
fn check_elements(mut content: &[u8], depth: usize) -> bool {
    while !content.is_empty() {
        let Some((element, rest)) = read(content) else {
            return false;
        };
        if !check_element(&element, depth) {
            return false;
        }
        content = rest;
    }
    true
}

fn check_element(element: &Element<'_>, depth: usize) -> bool {
    if depth > MAX_DEPTH {
        return false;
    }
    if element.class == UNIVERSAL {
        if !universal_form(element.tag, element.constructed) {
            return false;
        }
        if element.tag == TAG_BIT_STRING && !der_bit_string(element.content) {
            return false;
        }
    }
    !element.constructed || check_elements(element.content, depth + 1)
}

/// Whether `content` is the content of a DER BIT STRING: an initial octet of 0 to 7 unused
/// bits, 0 without further octets, and the unused bits zero (X.690 §8.6.2, §11.2.1).
fn der_bit_string(content: &[u8]) -> bool {
    match content {
        [0] => true,
        [unused @ 0..=7, .., last] => last & ((1u8 << unused) - 1) == 0,
        _ => false,
    }
}

/// Whether `content` is the content of an OBJECT IDENTIFIER within P12-041's bounds: 1 to
/// 39 octets, every subidentifier minimal (X.690 §8.19.2) and below 2^32.
fn check_oid(content: &[u8]) -> bool {
    if content.is_empty()
        || content.len() > MAX_OID_LENGTH
        || content.last().is_some_and(|&b| b & 0x80 != 0)
    {
        return false;
    }
    let mut value = 0u64;
    let mut start = true;
    for &b in content {
        if start && b == 0x80 {
            return false;
        }
        value = value << 7 | u64::from(b & 0x7f);
        if value > u64::from(u32::MAX) {
            return false;
        }
        start = b & 0x80 == 0;
        if start {
            value = 0;
        }
    }
    true
}

/// The content of the AlgorithmIdentifier: an OID within bounds and at most one parameters
/// element, which [`check_element`] has walked already.
fn check_algorithm(content: &[u8]) -> bool {
    let Some((oid, rest)) = read(content) else {
        return false;
    };
    if !oid.is(UNIVERSAL, false, TAG_OID) || !check_oid(oid.content) {
        return false;
    }
    rest.is_empty() || read(rest).is_some_and(|(_, rest)| rest.is_empty())
}

/// The next element of `fields`, which then holds the rest.
fn next<'a>(fields: &mut &'a [u8]) -> Option<Element<'a>> {
    let (element, rest) = read(fields)?;
    *fields = rest;
    Some(element)
}

/// Checks that `bytes` is exactly one DER `PrivateKeyInfo` (P12-041; `OneAsymmetricKey`,
/// RFC 5958 §2): version 0 or 1, an AlgorithmIdentifier, a non-empty privateKey,
/// attributes `[0]`, publicKey `[1]` only in version 1, nothing after it. A wrong password
/// on a file without MAC leaves valid padding in about 1 of 256 decryptions; the plaintext
/// is random then, and this check is what refuses it before it is returned as a key.
pub(crate) fn check_private_key_info(bytes: &[u8]) -> Result<(), Error> {
    let pki = match read(bytes) {
        Some((pki, [])) if pki.is(UNIVERSAL, true, TAG_SEQUENCE) && check_element(&pki, 0) => pki,
        _ => return Err(malformed("not one DER element of the types it may hold")),
    };
    let mut fields = pki.content;
    let version = match next(&mut fields) {
        Some(v) if v.is(UNIVERSAL, false, TAG_INTEGER) && matches!(v.content, [0 | 1]) => {
            v.content[0]
        }
        _ => return Err(malformed("version is not 0 or 1")),
    };
    if !next(&mut fields)
        .is_some_and(|a| a.is(UNIVERSAL, true, TAG_SEQUENCE) && check_algorithm(a.content))
    {
        return Err(malformed("cannot read the algorithm"));
    }
    if !next(&mut fields)
        .is_some_and(|k| k.is(UNIVERSAL, false, TAG_OCTET_STRING) && !k.content.is_empty())
    {
        return Err(malformed("cannot read the private key"));
    }
    if let Some((attributes, rest)) = read(fields)
        && attributes.is(CONTEXT, true, 0)
    {
        fields = rest;
    }
    if let Some((public_key, rest)) = read(fields)
        && version == 1
        && public_key.is(CONTEXT, false, 1)
    {
        if !der_bit_string(public_key.content) {
            return Err(malformed("public key is not a DER BIT STRING"));
        }
        fields = rest;
    }
    if !fields.is_empty() {
        return Err(malformed("trailing data"));
    }
    Ok(())
}

/// The keyBag PrivateKeyInfo `der`, normalised from BER, with a constructed publicKey `[1]`
/// joined into its primitive form. The BER to DER normalisation leaves it constructed,
/// since only the schema tells that this `[1]` is a BIT STRING (P12-002, as P12-005 for
/// encryptedContent). Input that is no DER SEQUENCE comes back unchanged for
/// [`check_private_key_info`] to refuse.
pub(crate) fn join_public_key(der: Zeroizing<Vec<u8>>) -> Result<Zeroizing<Vec<u8>>, Error> {
    let Some((pki, [])) = read(&der) else {
        return Ok(der);
    };
    if !pki.is(UNIVERSAL, true, TAG_SEQUENCE) {
        return Ok(der);
    }
    let mut public_keys = Vec::new();
    let mut parts = Vec::new();
    let mut content = pki.content;
    while !content.is_empty() {
        let Some((element, rest)) = read(content) else {
            parts.push(Some(content));
            break;
        };
        if element.is(CONTEXT, true, 1) {
            public_keys.push(element_of_public_key(element.content)?);
            parts.push(None);
        } else {
            parts.push(Some(&content[..content.len() - rest.len()]));
        }
        content = rest;
    }
    if public_keys.is_empty() {
        return Ok(der);
    }
    let mut joined = public_keys.iter();
    let slices: Vec<&[u8]> = parts
        .into_iter()
        .filter_map(|part| part.or_else(|| joined.next().map(|key| key.as_slice())))
        .collect();
    Ok(element(&[0x30], &slices))
}

/// The primitive `[1]` element of the segments of a constructed one.
fn element_of_public_key(segments: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
    Ok(element(&[0x81], &[&join_bit_string(segments)?]))
}

/// The value of a constructed BIT STRING from its segments: only the last may have unused
/// bits, and none has unused bits without bits (X.690 §8.6.2, §8.6.4).
fn join_bit_string(mut segments: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
    // Sized up front: a reallocation would leave a copy of the key unwiped.
    let mut value = Zeroizing::new(Vec::with_capacity(1 + segments.len()));
    value.push(0u8);
    while !segments.is_empty() {
        let (segment, rest) = read(segments)
            .filter(|(s, _)| s.is(UNIVERSAL, false, TAG_BIT_STRING) && value[0] == 0)
            .ok_or_else(|| malformed("invalid segment of the public key"))?;
        let (&unused, bits) = match segment.content {
            [unused @ 0..=7, bits @ ..] if *unused == 0 || !bits.is_empty() => (unused, bits),
            _ => return Err(malformed("invalid segment of the public key")),
        };
        value[0] = unused;
        value.extend_from_slice(bits);
        segments = rest;
    }
    Ok(value)
}
