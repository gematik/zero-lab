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

//! Durations in words, as this crate's messages give them; a front end uses the same for its
//! own text, so the two read alike.

/// A span of seconds in words, the two largest adjacent units: `1 year 4 months`,
/// `3 days`, `2 hours 1 minute`, `less than a minute`.
pub fn span(seconds: u64) -> String {
    const UNITS: [(u64, &str); 5] = [
        (365 * 86_400, "year"),
        (30 * 86_400, "month"),
        (86_400, "day"),
        (3_600, "hour"),
        (60, "minute"),
    ];
    let mut parts = Vec::new();
    let mut rest = seconds;
    for (size, name) in UNITS {
        if parts.len() == 2 {
            break;
        }
        let count = rest / size;
        if count > 0 {
            parts.push(format!(
                "{count} {name}{}",
                if count == 1 { "" } else { "s" }
            ));
            rest %= size;
        } else if !parts.is_empty() {
            break;
        }
    }
    if parts.is_empty() {
        "less than a minute".to_owned()
    } else {
        parts.join(" ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spans_in_words() {
        assert_eq!(span(0), "less than a minute");
        assert_eq!(span(3 * 86_400 + 5), "3 days");
        assert_eq!(
            span(365 * 86_400 + 4 * 30 * 86_400 + 86_400),
            "1 year 4 months"
        );
        assert_eq!(span(2 * 3_600 + 60), "2 hours 1 minute");
        assert_eq!(span(365 * 86_400 + 86_400), "1 year", "stops at a gap");
    }
}
