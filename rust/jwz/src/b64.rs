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

//! base64url without padding (RFC 7515 §2, RFC 4648 §5), strictly: padding, characters
//! outside the alphabet, whitespace and non-canonical trailing bits are refused, so a
//! value has exactly one encoding. Decoding is constant-time (`base64ct`).

use alloc::string::String;
use alloc::vec::Vec;

use base64ct::{Base64UrlUnpadded, Encoding};

use crate::error::{Error, ErrorCode};

/// The unpadded base64url encoding of `bytes`.
pub fn encode(bytes: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(bytes)
}

/// Decodes an unpadded base64url value; `context` names it in the error.
///
/// # Errors
///
/// [`ErrorCode::Base64`] for any value that is not the canonical encoding of its bytes.
pub fn decode(value: &str, context: &'static str) -> Result<Vec<u8>, Error> {
    // RFC 7515 §2: base64url "with all trailing '=' characters omitted".
    Base64UrlUnpadded::decode_vec(value).map_err(|_| Error::new(ErrorCode::Base64, context))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc_7515_2_round_trip() {
        assert_eq!(encode(b"\x03\xec\xff\xe0"), "A-z_4A");
        assert_eq!(decode("A-z_4A", "t").unwrap(), b"\x03\xec\xff\xe0");
        assert_eq!(decode("", "t").unwrap(), b"");
    }

    #[test]
    fn rfc_7515_2_padding_alphabet_and_trailing_bits_are_refused() {
        // padded, standard alphabet, whitespace, non-canonical last character
        for bad in ["A-z_4A==", "A+z/4A", "A-z_ 4A", "A-z_4B", "QQ=", "QR"] {
            assert_eq!(
                decode(bad, "t").map_err(|e| e.code()),
                Err(ErrorCode::Base64),
                "{bad}"
            );
        }
        assert_eq!(decode("QQ", "t").unwrap(), b"A");
    }
}
