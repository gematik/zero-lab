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

//! STORE-094: the key file of the `key-file` wrapper.

use zeroize::Zeroizing;

use super::StoreError;

/// Parses the content of a key file. `mode` is its POSIX mode, or `None` where the
/// platform has none; the caller reads both, this function does no I/O.
///
/// # Errors
///
/// `insecure_permissions` for a mode that lets group or others read; `malformed` for
/// anything but one strict base64 encoding of 32 bytes.
pub fn parse_kek_file(
    content: &[u8],
    mode: Option<u32>,
) -> Result<Zeroizing<[u8; 32]>, StoreError> {
    if mode.is_some_and(|m| m & 0o077 != 0) {
        return Err(StoreError::InsecurePermissions);
    }
    let text = content.strip_suffix(b"\n").unwrap_or(content);
    if text.len() != 44 {
        return Err(StoreError::Malformed("key file"));
    }
    let mut out = Zeroizing::new([0u8; 32]);
    decode_base64_32(text, &mut out).ok_or(StoreError::Malformed("key file"))?;
    Ok(out)
}

/// Strict standard base64 of exactly 32 bytes: 43 symbols, one `=`, and zero padding
/// bits (RFC 4648 §3.5), so that each key has one encoding.
fn decode_base64_32(text: &[u8], out: &mut [u8; 32]) -> Option<()> {
    fn value(c: u8) -> Option<u32> {
        Some(u32::from(match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        }))
    }
    if text[43] != b'=' {
        return None;
    }
    let mut acc: u32 = 0;
    let mut bits = 0;
    let mut n = 0;
    for &c in &text[..43] {
        acc = ((acc << 6) | value(c)?) & 0x3fff;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out[n] = u8::try_from((acc >> bits) & 0xff).expect("masked");
            n += 1;
        }
    }
    // 43 symbols carry 258 bits: 32 bytes and 2 padding bits, which must be zero.
    (n == 32 && acc & ((1 << bits) - 1) == 0).then_some(())
}
