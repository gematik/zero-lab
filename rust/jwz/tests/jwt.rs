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

//! JWT claims against RFC 7519: the claims set, NumericDate and `aud`. Expiry, issuer
//! and the time claims are tested next to the validation in `src/jwt.rs`.
#![cfg(feature = "jwt")]

use jwz::ErrorCode;
use jwz::jwt::{Claims, FixedClock};
use jwz::profile::{ClaimsPolicy, Profile};

fn parse(text: &str) -> Result<Claims, ErrorCode> {
    Claims::parse(text.as_bytes()).map_err(|e| e.code())
}

#[test]
fn rfc_7519_7_2_step_10_the_claims_set_is_a_json_object() {
    assert_eq!(parse(r#"{"iss":"a","exp":1}"#).unwrap().iss(), Some("a"));
    for (text, expected) in [
        ("[]", ErrorCode::Json),
        (r#""claims""#, ErrorCode::Json),
        (r#"{"iss":"a"} {}"#, ErrorCode::Json),
        (r#"{"iss":"a","iss":"b"}"#, ErrorCode::DuplicateMember),
    ] {
        assert_eq!(parse(text).err(), Some(expected), "{text}");
    }
    assert_eq!(
        Claims::parse(b"{\"iss\":\"\xff\"}")
            .map(|_| ())
            .map_err(|e| e.code()),
        Err(ErrorCode::Json),
        "not UTF-8"
    );
}

/// A NumericDate is a JSON number of seconds; a fraction is rounded down, and a
/// string, a negative number or one beyond 64 bits is not a date.
#[test]
fn rfc_7519_2_numeric_date_is_a_non_negative_number_of_seconds() {
    let exp = |text: &str| parse(text).unwrap().exp().map_err(|e| e.code());
    assert_eq!(exp(r#"{"exp":1300819380}"#), Ok(Some(1_300_819_380)));
    assert_eq!(exp(r#"{"exp":1300819380.999}"#), Ok(Some(1_300_819_380)));
    assert_eq!(exp(r#"{"exp":0}"#), Ok(Some(0)));
    assert_eq!(exp("{}"), Ok(None));
    for text in [
        r#"{"exp":"1300819380"}"#,
        r#"{"exp":-1}"#,
        r#"{"exp":-0.5}"#,
        r#"{"exp":1e20}"#,
        r#"{"exp":true}"#,
        r#"{"exp":null}"#,
    ] {
        assert_eq!(exp(text), Err(ErrorCode::InvalidClaim), "{text}");
    }
}

/// `aud` is one string or an array of strings, and a recipient that requires an
/// audience accepts the token only if it is one of them.
#[test]
fn rfc_7519_4_1_3_aud_is_a_string_or_an_array_of_strings() {
    let aud = |text: &str| {
        parse(text)
            .unwrap()
            .aud()
            .map(|a| a.into_iter().map(String::from).collect::<Vec<_>>())
            .map_err(|e| e.code())
    };
    assert_eq!(aud(r#"{"aud":"a"}"#), Ok(vec!["a".to_string()]));
    assert_eq!(
        aud(r#"{"aud":["a","b"]}"#),
        Ok(vec!["a".to_string(), "b".to_string()])
    );
    assert_eq!(aud("{}"), Ok(vec![]));
    for text in [r#"{"aud":1}"#, r#"{"aud":["a",1]}"#, r#"{"aud":{"a":1}}"#] {
        assert_eq!(aud(text), Err(ErrorCode::InvalidClaim), "{text}");
    }

    let policy = ClaimsPolicy {
        audience: Some("me".into()),
        require_exp: false,
        ..Profile::strict().claims
    };
    let validate = |text: &str| {
        parse(text)
            .unwrap()
            .validate(&policy, &FixedClock(0))
            .map_err(|e| e.code())
    };
    assert_eq!(validate(r#"{"aud":"me"}"#), Ok(()));
    assert_eq!(validate(r#"{"aud":["other","me"]}"#), Ok(()));
    for text in [
        r#"{"aud":"Me"}"#,
        r#"{"aud":["other"]}"#,
        r#"{"aud":[]}"#,
        "{}",
    ] {
        assert_eq!(validate(text), Err(ErrorCode::InvalidClaim), "{text}");
    }
}
