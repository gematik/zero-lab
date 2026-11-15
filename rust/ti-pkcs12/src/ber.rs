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

//! BER to DER (X.690 §8 to §10) for what PKCS#12 producers write inside a safe: indefinite
//! and non-minimal lengths, constructed (segmented) strings. `der` in BER mode reads these,
//! but an [`Any`](der::asn1::Any) keeps its nested content as written, so a plain keyBag's
//! PrivateKeyInfo is normalised here, every layer, before P12-041 checks it as DER (P12-002).
//! Content is not reordered: no signature covers a SET in PKCS#12. go/pkcs12's
//! internal/ber does the same.

use crate::Error;

/// A PKCS#12 layer nests about ten levels; the bound keeps hostile input off the stack.
const MAX_DEPTH: usize = 64;

const CONSTRUCTED: u8 = 0x20;
const TAG_BIT_STRING: u64 = 3;
const TAG_OCTET_STRING: u64 = 4;

fn malformed(reason: &str) -> Error {
    Error::malformed("BER", reason)
}

/// The DER encoding of the single BER element `bytes`; trailing bytes are an error.
pub(crate) fn to_der(bytes: &[u8]) -> Result<Vec<u8>, Error> {
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
        // High tag number form (X.690 §8.1.2.4): base 128, most significant first.
        tag = 0;
        loop {
            let &b = bytes.get(i).ok_or_else(|| malformed("truncated tag"))?;
            if tag > 1 << 56 {
                return Err(malformed("tag number too large"));
            }
            i += 1;
            tag = tag << 7 | u64::from(b & 0x7f);
            if b & 0x80 == 0 {
                break;
            }
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
fn convert(bytes: &[u8], depth: usize) -> Result<(Vec<u8>, &[u8]), Error> {
    if depth > MAX_DEPTH {
        return Err(malformed("nesting too deep"));
    }
    let h = read_header(bytes)?;
    let body = &bytes[h.size..];
    if !h.constructed {
        // read_header refuses an indefinite primitive and a length past the end.
        let length = h.length.unwrap_or_default();
        return Ok((element(h.ident, &body[..length]), &body[length..]));
    }
    let (children, rest) = read_children(body, h.length, depth)?;
    if h.universal && is_string(h.tag) {
        // A constructed string is primitive in DER (X.690 §10.2).
        let value = join_segments(h.tag, &children, depth)?;
        let mut ident = h.ident.to_vec();
        ident[0] &= !CONSTRUCTED;
        return Ok((element(&ident, &value), rest));
    }
    let mut content = Vec::new();
    for child in children {
        content.extend(convert(child, depth + 1)?.0);
    }
    Ok((element(h.ident, &content), rest))
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
fn join_segments(tag: u64, segments: &[&[u8]], depth: usize) -> Result<Vec<u8>, Error> {
    let mut value = Vec::new();
    for (i, segment) in segments.iter().enumerate() {
        let (der, _) = convert(segment, depth + 1)?;
        let h = read_header(&der)?;
        if !h.universal || h.tag != tag {
            return Err(malformed("segment of a constructed string has another tag"));
        }
        let mut part = &der[h.size..];
        if tag == TAG_BIT_STRING {
            // Each segment starts with its unused-bits count; only the last may have
            // unused bits (X.690 §8.6.4).
            let (&unused, bits) = part
                .split_first()
                .filter(|&(&unused, _)| unused == 0 || i == segments.len() - 1)
                .ok_or_else(|| malformed("invalid BIT STRING segment"))?;
            match value.first_mut() {
                None => value.push(unused),
                Some(first) => *first = unused,
            }
            part = bits;
        }
        value.extend_from_slice(part);
    }
    if tag == TAG_BIT_STRING && segments.is_empty() {
        value.push(0);
    }
    Ok(value)
}

/// Universal string types BER may write constructed (X.690 §8.6, §8.7, §8.23).
fn is_string(tag: u64) -> bool {
    matches!(
        tag,
        TAG_BIT_STRING | TAG_OCTET_STRING | 12 | 18..=22 | 25..=28 | 30
    )
}

/// `ident`, a minimal definite length and `content`.
fn element(ident: &[u8], content: &[u8]) -> Vec<u8> {
    let mut out = ident.to_vec();
    let len = content.len();
    if let Ok(short) = u8::try_from(len)
        && short < 0x80
    {
        out.push(short);
    } else {
        let octets = len.to_be_bytes();
        let skip = octets.iter().take_while(|&&b| b == 0).count();
        let long = &octets[skip..];
        out.push(0x80 | u8::try_from(long.len()).unwrap_or(0x7f));
        out.extend_from_slice(long);
    }
    out.extend_from_slice(content);
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

    /// P12-002: indefinite lengths, non-minimal lengths and segmented strings become DER,
    /// in every layer.
    #[test]
    fn p12_002_ber_becomes_der_in_every_layer() {
        for (ber, der) in [
            ("3080 0201 00 0000", "3003 020100"),
            ("3081 03 020100", "3003 020100"),
            ("3080 3080 0603 2b6570 0000 0000", "3007 3005 06032b6570"),
            ("2480 0401 aa 0402 bbcc 0000", "0403 aabbcc"),
            ("2406 0401 aa 0401 bb", "0402 aabb"),
            ("2380 0302 00aa 0302 04bb 0000", "0303 04aabb"),
            ("a080 0401 aa 0000", "a003 0401aa"),
        ] {
            assert_eq!(to_der(&bytes(ber)).unwrap(), bytes(der), "{ber}");
        }
        let long = [0x04, 0x82, 0x00, 0x81]
            .into_iter()
            .chain([0u8; 0x81])
            .collect::<Vec<_>>();
        assert_eq!(to_der(&long).unwrap()[..3], [0x04, 0x81, 0x81]);
    }

    /// X.690 §8: what is not BER stays an error.
    #[test]
    fn malformed_ber_is_refused() {
        for ber in [
            "",
            "30",
            "3080 020100",
            "0480 aa 0000",
            "3003 0201",
            "3003 020100 00",
            "2403 0201 00",
            "2380 0302 01aa 0302 00bb 0000",
            "30ff",
        ] {
            assert!(
                matches!(to_der(&bytes(ber)), Err(Error::Malformed { .. })),
                "{ber}"
            );
        }
    }
}
