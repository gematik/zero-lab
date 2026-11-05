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

//! Base64 (RFC 4648 section 4, with padding) for what the Konnektor and a `.kon` file carry, in
//! constant time. Whitespace, as line-wrapping encoders leave it, is ignored when decoding; an
//! encoding with non-zero padding bits is refused.

use base64ct::{Base64, Encoding as _};

pub(crate) fn encode(bytes: impl AsRef<[u8]>) -> String {
    Base64::encode_string(bytes.as_ref())
}

pub(crate) fn decode(text: &str) -> Result<Vec<u8>, base64ct::Error> {
    let compact: String = text.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    Base64::decode_vec(&compact)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn whitespace_is_ignored_and_a_non_canonical_encoding_refused() {
        assert_eq!(decode("aGVs\r\n bG8=").unwrap(), b"hello");
        assert!(decode("aGVsbG9=").is_err());
        assert!(decode("aGVsbG8").is_err());
        assert_eq!(encode(b"hello?>"), "aGVsbG8/Pg==");
    }
}
