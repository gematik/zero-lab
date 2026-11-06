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

//! The freshness a response's `Cache-Control` grants (RFC 9111 §5.2), for a private
//! client cache.

use core::time::Duration;

/// RFC 9111 §1.2.2: a delta-seconds too large to represent counts as 2^31.
const DELTA_SECONDS_CAP: u64 = 2_147_483_648;

/// What a `Cache-Control` field value says about how long its response stays fresh.
///
/// Only what decides a private cache's freshness is read: `max-age`, `no-cache` and
/// `no-store`. Other directives, `s-maxage` among them, are ignored, as RFC 9111 §5.2.3
/// requires of unrecognised ones. Anything doubtful makes the response stale rather than
/// fresh: a field that does not parse as a list of directives, a `max-age` that is not
/// delta-seconds or that repeats (RFC 9111 §4.2.1), and `no-cache` also in its qualified
/// form.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CacheControl {
    freshness: Option<Duration>,
}

impl CacheControl {
    /// Reads `value`, the field value; several `Cache-Control` lines are one value joined
    /// with `, ` (RFC 9110 §5.3).
    pub fn parse(value: &str) -> CacheControl {
        let Some(directives) = directives(value) else {
            return CacheControl::STALE;
        };
        let mut max_age = None;
        let mut revalidate = false;
        for (name, argument) in directives {
            if name.eq_ignore_ascii_case("max-age") {
                let Some(seconds) = argument.and_then(delta_seconds) else {
                    return CacheControl::STALE;
                };
                if max_age.replace(seconds).is_some() {
                    return CacheControl::STALE;
                }
            } else if name.eq_ignore_ascii_case("no-cache") || name.eq_ignore_ascii_case("no-store")
            {
                revalidate = true;
            }
        }
        CacheControl {
            freshness: if revalidate {
                Some(Duration::ZERO)
            } else {
                max_age.map(Duration::from_secs)
            },
        }
    }

    const STALE: CacheControl = CacheControl {
        freshness: Some(Duration::ZERO),
    };

    /// How long the response is fresh: `max-age`, zero when it must be revalidated or the
    /// field is doubtful, `None` when the field states no lifetime.
    pub fn freshness(&self) -> Option<Duration> {
        self.freshness
    }
}

/// RFC 9111 §1.2.2: delta-seconds is `1*DIGIT`, in token form only (§5.2.2.1).
fn delta_seconds(argument: Argument<'_>) -> Option<u64> {
    let Argument::Token(digits) = argument else {
        return None;
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some(
        digits
            .bytes()
            .try_fold(0u64, |n, d| {
                n.checked_mul(10)?.checked_add(u64::from(d - b'0'))
            })
            .map_or(DELTA_SECONDS_CAP, |n| n.min(DELTA_SECONDS_CAP)),
    )
}

/// A directive's argument (RFC 9111 §5.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Argument<'a> {
    Token(&'a str),
    Quoted,
}

/// The directives of `value`, `#( token [ "=" ( token / quoted-string ) ] )` (RFC 9111
/// §5.2, RFC 9110 §5.6.1), or `None` if it is not one. Empty list elements are allowed.
fn directives(value: &str) -> Option<Vec<(&str, Option<Argument<'_>>)>> {
    let bytes = value.as_bytes();
    let mut at = 0;
    let mut out = Vec::new();
    loop {
        at = skip_ows(bytes, at);
        if at == bytes.len() {
            return Some(out);
        }
        if bytes[at] == b',' {
            at += 1;
            continue;
        }
        let name_end = token_end(bytes, at);
        if name_end == at {
            return None;
        }
        let name = &value[at..name_end];
        at = name_end;
        let mut argument = None;
        if bytes.get(at) == Some(&b'=') {
            at += 1;
            if bytes.get(at) == Some(&b'"') {
                at = quoted_string_end(bytes, at)?;
                argument = Some(Argument::Quoted);
            } else {
                let end = token_end(bytes, at);
                if end == at {
                    return None;
                }
                argument = Some(Argument::Token(&value[at..end]));
                at = end;
            }
        }
        out.push((name, argument));
        at = skip_ows(bytes, at);
        match bytes.get(at) {
            None => return Some(out),
            Some(b',') => at += 1,
            Some(_) => return None,
        }
    }
}

fn skip_ows(bytes: &[u8], mut at: usize) -> usize {
    while matches!(bytes.get(at), Some(b' ' | b'\t')) {
        at += 1;
    }
    at
}

/// RFC 9110 §5.6.2: `tchar`.
fn token_end(bytes: &[u8], mut at: usize) -> usize {
    while bytes
        .get(at)
        .is_some_and(|&b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
    {
        at += 1;
    }
    at
}

/// RFC 9110 §5.6.4: the index after the closing quote of the quoted-string at `at`.
fn quoted_string_end(bytes: &[u8], mut at: usize) -> Option<usize> {
    at += 1;
    loop {
        match *bytes.get(at)? {
            b'"' => return Some(at + 1),
            b'\\' => {
                let escaped = *bytes.get(at + 1)?;
                if !(escaped == b'\t' || (b' '..=b'~').contains(&escaped) || escaped >= 0x80) {
                    return None;
                }
                at += 2;
            }
            b if b == b'\t'
                || b == b' '
                || b == b'!'
                || (0x23..=0x5b).contains(&b)
                || (0x5d..=0x7e).contains(&b)
                || b >= 0x80 =>
            {
                at += 1;
            }
            _ => return None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh(value: &str) -> Option<u64> {
        CacheControl::parse(value).freshness().map(|d| d.as_secs())
    }

    #[test]
    fn rfc_9111_5_2_2_1_max_age_is_delta_seconds_in_token_form() {
        assert_eq!(fresh("max-age=300"), Some(300));
        assert_eq!(fresh("public, MAX-AGE=0"), Some(0));
        assert_eq!(fresh("  max-age=60 ,public"), Some(60));
        for doubtful in [
            r#"max-age="300""#,
            "max-age=",
            "max-age",
            "max-age=-1",
            "max-age=3.5",
            "max-age=1e3",
        ] {
            assert_eq!(fresh(doubtful), Some(0), "{doubtful}");
        }
    }

    #[test]
    fn rfc_9111_1_2_2_a_delta_seconds_too_large_counts_as_two_to_the_31() {
        assert_eq!(
            fresh("max-age=99999999999999999999999"),
            Some(2_147_483_648)
        );
        assert_eq!(fresh("max-age=2147483649"), Some(2_147_483_648));
    }

    #[test]
    fn rfc_9111_4_2_1_a_repeated_max_age_makes_the_response_stale() {
        assert_eq!(fresh("max-age=60, max-age=60"), Some(0));
    }

    #[test]
    fn rfc_9111_5_2_2_4_no_cache_and_5_2_2_5_no_store_mean_revalidate_every_time() {
        for value in [
            "no-cache",
            "no-store",
            "max-age=3600, no-cache",
            r#"no-cache="set-cookie", max-age=3600"#,
        ] {
            assert_eq!(fresh(value), Some(0), "{value}");
        }
    }

    #[test]
    fn rfc_9111_5_2_3_unknown_directives_are_ignored() {
        assert_eq!(
            fresh(r#"public, ext="a, b", s-maxage=9, max-age=30"#),
            Some(30)
        );
        assert_eq!(fresh("public"), None);
        assert_eq!(fresh(""), None);
        assert_eq!(fresh(" , ,"), None);
    }

    /// RFC 9110 §5.6.1, §5.6.4: a field that is not a list of directives says nothing
    /// a cache may rely on.
    #[test]
    fn rfc_9110_5_6_a_field_that_does_not_parse_makes_the_response_stale() {
        for broken in [
            "max-age=60 public",
            r#"ext="unterminated, max-age=60"#,
            "=60",
            "max-age=60;",
            "max-age=6\u{0}0",
        ] {
            assert_eq!(fresh(broken), Some(0), "{broken:?}");
        }
    }
}
