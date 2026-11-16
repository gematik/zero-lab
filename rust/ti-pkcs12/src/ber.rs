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

//! BER to DER (X.690 §8 to §10) for what PKCS#12 producers write: indefinite and
//! non-minimal lengths, constructed (segmented) strings. The PFX, the authSafe octets and
//! every safe are normalised here before `der` reads them (P12-002): `der` in BER mode
//! refuses constructed strings other than OCTET STRING inside an indefinite length, and an
//! [`Any`](der::asn1::Any) keeps its nested content as written, so a plain keyBag's
//! PrivateKeyInfo would reach P12-041 in BER. Nesting counts from each layer's outermost
//! element, as go/pkcs12 counts it (P12-004).
//! Content is not reordered: no signature covers a SET in PKCS#12. go/pkcs12's
//! internal/ber does the same.
//!
//! What passes through here is a private key: every buffer that holds content is
//! [`Zeroizing`] and allocated at its final size, so no copy outlives the call unwiped.

use zeroize::Zeroizing;

use crate::Error;

/// A PKCS#12 layer nests about ten levels; the bound keeps hostile input off the stack.
const MAX_DEPTH: usize = 64;

const CONSTRUCTED: u8 = 0x20;
const TAG_BIT_STRING: u64 = 3;
const TAG_OCTET_STRING: u64 = 4;

fn malformed(reason: &str) -> Error {
    Error::malformed("BER", reason)
}

/// The DER encoding of the single BER element `bytes`, its outermost element at depth 0
/// (P12-004); trailing bytes are an error.
pub(crate) fn to_der(bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
    let (der, rest) = convert(bytes, 0)?;
    if !rest.is_empty() {
        return Err(malformed("trailing bytes"));
    }
    Ok(der)
}

/// A decoded identifier and length.
struct Header<'a> {
    ident: &'a [u8],
    universal: bool,
    tag: u64,
    constructed: bool,
    /// `None` for an indefinite length.
    length: Option<usize>,
    size: usize,
}

fn read_header(bytes: &[u8]) -> Result<Header<'_>, Error> {
    let &first = bytes.first().ok_or_else(|| malformed("truncated header"))?;
    let universal = first & 0xc0 == 0;
    let constructed = first & CONSTRUCTED != 0;
    let mut i = 1;
    let mut tag = u64::from(first & 0x1f);
    if tag == 0x1f {
        // High tag number form (X.690 §8.1.2.4): base 128, most significant first, with no
        // leading zero group, only for numbers the low form cannot hold, and, as `der`
        // reads them, at most 32 bits.
        tag = 0;
        loop {
            let &b = bytes.get(i).ok_or_else(|| malformed("truncated tag"))?;
            if tag > u64::from(u32::MAX) >> 7 {
                return Err(malformed("tag number too large"));
            }
            if i == 1 && b == 0x80 {
                return Err(malformed("tag number with a leading zero group"));
            }
            i += 1;
            tag = tag << 7 | u64::from(b & 0x7f);
            if b & 0x80 == 0 {
                break;
            }
        }
        if tag < 0x1f {
            return Err(malformed("tag number in the high form below 31"));
        }
    }
    let ident = &bytes[..i];
    // Universal tag 0 is end-of-contents (X.690 §8.1.5), which read_children consumes.
    if universal && tag == 0 {
        return Err(malformed("unexpected end-of-contents"));
    }
    let &len = bytes.get(i).ok_or_else(|| malformed("truncated length"))?;
    i += 1;
    let length = match len {
        0..0x80 => Some(usize::from(len)),
        0x80 if constructed => None,
        0x80 => return Err(malformed("indefinite length on a primitive element")),
        0xff => return Err(malformed("reserved length octet")),
        _ => {
            let n = usize::from(len & 0x7f);
            let octets = bytes
                .get(i..i + n)
                .filter(|_| n <= 4)
                .ok_or_else(|| malformed("unsupported or truncated length"))?;
            i += n;
            let value = octets.iter().fold(0u64, |acc, &b| acc << 8 | u64::from(b));
            Some(usize::try_from(value).map_err(|_| malformed("length overflows usize"))?)
        }
    };
    if length.is_some_and(|l| l > bytes.len() - i) {
        return Err(malformed("length exceeds the bytes available"));
    }
    Ok(Header {
        ident,
        universal,
        tag,
        constructed,
        length,
        size: i,
    })
}

/// Converts the element at the start of `bytes`; returns it and the bytes after it.
fn convert(bytes: &[u8], depth: usize) -> Result<(Zeroizing<Vec<u8>>, &[u8]), Error> {
    if depth > MAX_DEPTH {
        return Err(malformed("nesting too deep"));
    }
    let h = read_header(bytes)?;
    if h.universal {
        check_universal(&h)?;
    }
    let body = &bytes[h.size..];
    if !h.constructed {
        // read_header refuses an indefinite primitive and a length past the end.
        let length = h.length.unwrap_or_default();
        return Ok((element(h.ident, &[&body[..length]]), &body[length..]));
    }
    let (children, rest) = read_children(body, h.length, depth)?;
    if h.universal && is_string(h.tag) {
        // A constructed string is primitive in DER (X.690 §10.2).
        let value = join_segments(h.tag, &children, depth)?;
        let mut ident = h.ident.to_vec();
        ident[0] &= !CONSTRUCTED;
        return Ok((element(&ident, &[&value]), rest));
    }
    let parts = children
        .iter()
        .map(|child| Ok(convert(child, depth + 1)?.0))
        .collect::<Result<Vec<_>, Error>>()?;
    let parts: Vec<&[u8]> = parts.iter().map(|part| part.as_slice()).collect();
    Ok((element(h.ident, &parts), rest))
}

/// Splits the content of a constructed element into its children (still BER); returns
/// them and the bytes after the element.
fn read_children(
    bytes: &[u8],
    length: Option<usize>,
    depth: usize,
) -> Result<(Vec<&[u8]>, &[u8]), Error> {
    let mut children = Vec::new();
    if let Some(length) = length {
        let (mut content, rest) = bytes.split_at(length);
        while !content.is_empty() {
            let (child, next) = content.split_at(element_size(content, depth + 1)?);
            children.push(child);
            content = next;
        }
        return Ok((children, rest));
    }
    // Indefinite length: children until the end-of-contents octets 00 00.
    let mut content = bytes;
    loop {
        match content {
            [0, 0, rest @ ..] => return Ok((children, rest)),
            [_, _, ..] => {
                let (child, next) = content.split_at(element_size(content, depth + 1)?);
                children.push(child);
                content = next;
            }
            _ => return Err(malformed("missing end-of-contents")),
        }
    }
}

/// The bytes the element at the start of `bytes` occupies, end-of-contents included.
fn element_size(bytes: &[u8], depth: usize) -> Result<usize, Error> {
    if depth > MAX_DEPTH {
        return Err(malformed("nesting too deep"));
    }
    let h = read_header(bytes)?;
    if let Some(length) = h.length {
        return Ok(h.size + length);
    }
    let (_, rest) = read_children(&bytes[h.size..], None, depth)?;
    Ok(bytes.len() - rest.len())
}

/// The concatenated segments of a constructed string: each of the same universal tag,
/// constructed themselves or not (X.690 §8.21.4).
fn join_segments(tag: u64, segments: &[&[u8]], depth: usize) -> Result<Zeroizing<Vec<u8>>, Error> {
    let mut ders = Vec::with_capacity(segments.len());
    for segment in segments {
        let (der, _) = convert(segment, depth + 1)?;
        let h = read_header(&der)?;
        if !h.universal || h.tag != tag {
            return Err(malformed("segment of a constructed string has another tag"));
        }
        let size = h.size;
        ders.push((der, size));
    }
    let mut parts: Vec<&[u8]> = ders.iter().map(|(der, size)| &der[*size..]).collect();
    let mut unused = Vec::new();
    if tag == TAG_BIT_STRING {
        // Each segment starts with its unused-bits count; only the last may have unused
        // bits (X.690 §8.6.4). The joined string carries the last count once.
        let last = parts.len().saturating_sub(1);
        for (i, part) in parts.iter_mut().enumerate() {
            // A count of 0 to 7, 0 when no bits follow (X.690 §8.6.2): joined, a last
            // segment of unused bits without bits would pass for a valid count.
            let (&count, bits) = part
                .split_first()
                .filter(|&(&count, bits)| {
                    count == 0 || (i == last && count <= 7 && !bits.is_empty())
                })
                .ok_or_else(|| malformed("invalid BIT STRING segment"))?;
            if i == last {
                unused.push(count);
            }
            *part = bits;
        }
        if parts.is_empty() {
            unused.push(0);
        }
    }
    let mut value = Zeroizing::new(Vec::with_capacity(
        unused.len() + parts.iter().map(|part| part.len()).sum::<usize>(),
    ));
    value.extend_from_slice(&unused);
    for part in parts {
        value.extend_from_slice(part);
    }
    Ok(value)
}

/// Refuses a universal element whose DER form `der` does not read: every layer is read with
/// it after this normalisation, and go/pkcs12 refuses the same set (P12-002). Constructed
/// strings are judged by the primitive form they become.
fn check_universal(h: &Header<'_>) -> Result<(), Error> {
    let known = match (h.tag, h.constructed) {
        (0x10 | 0x11, true)
        | (0x01..=0x06 | 0x09 | 0x0a | 0x0c | 0x0d | 0x12..=0x18 | 0x1a | 0x1b | 0x1e, false) => {
            true
        }
        (tag, true) => is_string(tag) && known_string(tag),
        _ => false,
    };
    if known && h.ident.len() == 1 {
        Ok(())
    } else {
        Err(malformed("universal type outside what DER is read with"))
    }
}

/// The string types of [`is_string`] that `der` reads.
fn known_string(tag: u64) -> bool {
    matches!(tag, 0x03 | 0x04 | 0x0c | 0x12..=0x16 | 0x1a | 0x1b | 0x1e)
}

/// Universal string types BER may write constructed (X.690 §8.6, §8.7, §8.23).
fn is_string(tag: u64) -> bool {
    matches!(
        tag,
        TAG_BIT_STRING | TAG_OCTET_STRING | 12 | 18..=22 | 25..=28 | 30
    )
}

/// `ident`, a minimal definite length and the concatenated `parts`, in a buffer of
/// exactly that size.
pub(crate) fn element(ident: &[u8], parts: &[&[u8]]) -> Zeroizing<Vec<u8>> {
    let len: usize = parts.iter().map(|part| part.len()).sum();
    let octets = len.to_be_bytes();
    let long = &octets[octets.iter().take_while(|&&b| b == 0).count()..];
    let mut out = Zeroizing::new(Vec::with_capacity(ident.len() + 1 + long.len() + len));
    out.extend_from_slice(ident);
    if let Ok(short) = u8::try_from(len)
        && short < 0x80
    {
        out.push(short);
    } else {
        out.push(0x80 | u8::try_from(long.len()).unwrap_or(0x7f));
        out.extend_from_slice(long);
    }
    for part in parts {
        out.extend_from_slice(part);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes(hex: &str) -> Vec<u8> {
        let hex: String = hex.split_whitespace().collect();
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    /// The DER of an element of tag `ident` around `content`.
    fn der(ident: u8, content: &[u8]) -> Vec<u8> {
        element(&[ident], &[content]).to_vec()
    }

    /// Re-encodes DER as legacy producers write it: every constructed element with an
    /// indefinite length, every OCTET STRING longer than `segment` in segments.
    fn to_ber(mut der: &[u8], segment: usize) -> Vec<u8> {
        let mut out = Vec::new();
        while !der.is_empty() {
            let h = read_header(der).unwrap();
            let length = h.length.unwrap();
            let content = &der[h.size..h.size + length];
            if h.constructed {
                out.extend_from_slice(h.ident);
                out.push(0x80);
                out.extend(to_ber(content, segment));
                out.extend([0, 0]);
            } else if h.universal && h.tag == TAG_OCTET_STRING && content.len() > segment {
                out.extend([h.ident[0] | CONSTRUCTED, 0x80]);
                for chunk in content.chunks(segment) {
                    out.extend(super::tests::der(h.ident[0], chunk));
                }
                out.extend([0, 0]);
            } else {
                out.extend_from_slice(&der[..h.size + length]);
            }
            der = &der[h.size + length..];
        }
        out
    }

    /// P12-002: indefinite lengths, non-minimal lengths and segmented strings become DER,
    /// in every layer; the cases of go/pkcs12's internal/ber TestToDER.
    #[test]
    fn p12_002_ber_becomes_der_in_every_layer() {
        for (name, ber, der) in [
            // X.690 §8.6.4.2: the BIT STRING '0A3B5F291CD'H, primitive and as a
            // constructed indefinite-length encoding of two segments.
            (
                "X.690 8.6.4.2 primitive",
                "03 07 04 0A 3B 5F 29 1C D0",
                "03 07 04 0A 3B 5F 29 1C D0",
            ),
            (
                "X.690 8.6.4.2 constructed",
                "23 80 03 03 00 0A 3B 03 05 04 5F 29 1C D0 00 00",
                "03 07 04 0A 3B 5F 29 1C D0",
            ),
            (
                "DER passes through",
                "30 06 02 01 03 04 01 AA",
                "30 06 02 01 03 04 01 AA",
            ),
            (
                "indefinite SEQUENCE",
                "30 80 02 01 03 00 00",
                "30 03 02 01 03",
            ),
            (
                "nested indefinite",
                "30 80 30 80 05 00 00 00 00 00",
                "30 04 30 02 05 00",
            ),
            (
                "segmented OCTET STRING",
                "24 80 04 02 01 02 04 01 03 00 00",
                "04 03 01 02 03",
            ),
            (
                "definite segmented OCTET STRING",
                "24 07 04 02 01 02 04 01 03",
                "04 03 01 02 03",
            ),
            (
                "nested segments",
                "24 80 24 80 04 01 01 00 00 04 01 02 00 00",
                "04 02 01 02",
            ),
            ("empty constructed OCTET STRING", "24 80 00 00", "04 00"),
            ("empty constructed BIT STRING", "23 80 00 00", "03 01 00"),
            (
                "segmented BMPString",
                "3E 80 1E 02 00 41 1E 02 00 42 00 00",
                "1E 04 00 41 00 42",
            ),
            ("non-minimal length", "04 82 00 02 AA BB", "04 02 AA BB"),
            (
                "context-specific constructed keeps form",
                "A0 80 04 01 AA 00 00",
                "A0 03 04 01 AA",
            ),
            (
                "high tag number",
                "BF 81 00 80 05 00 00 00",
                "BF 81 00 02 05 00",
            ),
            ("high tag number 31", "DF 1F 00", "DF 1F 00"),
            (
                "high tag number 2^32-1",
                "9F 8F FF FF FF 7F 00",
                "9F 8F FF FF FF 7F 00",
            ),
            (
                "BIT STRING last segment empty",
                "23 80 03 02 00 0A 03 01 00 00 00",
                "03 02 00 0A",
            ),
        ] {
            assert_eq!(*to_der(&bytes(ber)).unwrap(), bytes(der), "{name}");
        }
    }

    /// P12-002: a long OCTET STRING in segments of a three-byte length round-trips.
    #[test]
    fn p12_002_long_content_round_trips() {
        let der = der(0x04, &vec![0x5a; 70_000]);
        assert_eq!(*to_der(&to_ber(&der, 1000)).unwrap(), der);
    }

    /// X.690 §8: what is not BER stays an error; the cases of go/pkcs12's internal/ber
    /// TestToDERRejects, and the tag forms `der` refuses.
    #[test]
    fn malformed_ber_is_refused() {
        let too_deep = [
            [0x30, 0x80].repeat(MAX_DEPTH + 2),
            [0, 0].repeat(MAX_DEPTH + 2),
        ]
        .concat();
        for (name, ber) in [
            ("empty", Vec::new()),
            ("truncated header", bytes("30")),
            ("length beyond input", bytes("04 05 01 02")),
            ("missing end-of-contents", bytes("30 80 05 00")),
            ("indefinite primitive", bytes("04 80 01 00 00")),
            ("reserved length octet", bytes("04 FF 00")),
            ("five-byte length", bytes("04 85 00 00 00 00 01 AA")),
            ("trailing data", bytes("05 00 00")),
            ("segment with other tag", bytes("24 80 0C 01 41 00 00")),
            (
                "BIT STRING segment with unused bits",
                bytes("23 80 03 02 04 0A 03 02 00 3B 00 00"),
            ),
            ("empty BIT STRING segment", bytes("23 80 03 00 00 00")),
            ("truncated high tag", bytes("1F 81")),
            ("end-of-contents as element", bytes("30 04 30 02 00 00")),
            ("too deep", too_deep),
            ("high tag number below 31", bytes("A0 80 FF 09 00 00 00")),
            (
                "high tag number with a leading zero group",
                bytes("1F 80 1F 00"),
            ),
            (
                "high tag number above 32 bits",
                bytes("7F 9E 82 A0 FF FF FF 00 00"),
            ),
            ("high tag number 2^32", bytes("9F 90 80 80 80 00 00")),
            (
                "BIT STRING segment with unused bits above 7",
                bytes("23 80 03 02 00 0A 03 02 08 00 00 00"),
            ),
            (
                "BIT STRING segment with unused bits and no bits",
                bytes("23 80 03 02 00 A0 03 01 05 00 00"),
            ),
            ("universal tag 15", bytes("0F 00")),
            ("primitive SEQUENCE", bytes("10 00")),
            ("constructed INTEGER", bytes("22 03 02 01 00")),
            ("segmented GraphicString", bytes("39 80 19 01 41 00 00")),
            ("UniversalString", bytes("1C 00")),
            ("universal type in the high form", bytes("1F 81 00 00")),
        ] {
            assert!(
                matches!(to_der(&ber), Err(Error::Malformed { .. })),
                "{name}"
            );
        }
    }

    /// The bound of MAX_DEPTH nested elements holds, one more does not.
    #[test]
    fn nesting_is_bounded_at_max_depth() {
        let nested = |levels: usize| {
            [
                [0x30, 0x80].repeat(levels),
                vec![0x05, 0x00],
                [0, 0].repeat(levels),
            ]
            .concat()
        };
        assert!(to_der(&nested(MAX_DEPTH)).is_ok());
        assert!(to_der(&nested(MAX_DEPTH + 2)).is_err());
    }
}
