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

//! The compact serialization's outer layer: a size cap, then exactly `N` parts separated
//! by `.` (RFC 7515 §7.1: five for JWE in RFC 7516 §7.1, three for JWS). Nothing is
//! decoded here; the parts are returned as the text between the dots.

use crate::error::{Error, ErrorCode};

/// The `N` dot-separated parts of `token`, if it is at most `max_len` bytes and has
/// exactly `N` parts.
///
/// # Errors
///
/// [`ErrorCode::TokenTooLarge`] above `max_len` (checked before anything else),
/// [`ErrorCode::Malformed`] for any other number of parts.
pub fn split<const N: usize>(token: &str, max_len: usize) -> Result<[&str; N], Error> {
    if token.len() > max_len {
        return Err(Error::new(
            ErrorCode::TokenTooLarge,
            "compact serialization",
        ));
    }
    let malformed = Error::new(ErrorCode::Malformed, "compact serialization");
    let mut parts = [""; N];
    let mut pieces = token.split('.');
    for part in &mut parts {
        *part = pieces.next().ok_or(malformed)?;
    }
    if pieces.next().is_some() {
        return Err(malformed);
    }
    Ok(parts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc_7515_7_1_exactly_three_parts() {
        assert_eq!(split::<3>("a.b.c", 100).unwrap(), ["a", "b", "c"]);
        assert_eq!(split::<3>("a..c", 100).unwrap(), ["a", "", "c"]);
        for bad in ["a.b", "a.b.c.d", "abc", ""] {
            assert_eq!(
                split::<3>(bad, 100).map_err(|e| e.code()),
                Err(ErrorCode::Malformed),
                "{bad}"
            );
        }
    }

    #[test]
    fn size_cap_comes_first() {
        assert_eq!(
            split::<3>("a.b.c.d.e.f", 5).map_err(|e| e.code()),
            Err(ErrorCode::TokenTooLarge)
        );
        assert!(split::<5>("a.b.c.d.e", 9).is_ok());
    }
}
