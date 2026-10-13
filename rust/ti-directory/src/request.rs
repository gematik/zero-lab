/*
 * Copyright (Change Date see Readme), gematik GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * *******
 *
 * For additional notes and disclaimer from gematik and in case of changes
 * by gematik, find details in the "Readme" file.
 */

//! The requests every path shares, and how a refusal reads.

use base64ct::{Base64, Encoding};
use ti_idpd::http::{Method, Request, Response};

use crate::error::{DirectoryError, Error};

/// `GET url`, asking for JSON, not following redirects.
pub(crate) fn get(url: &str) -> Request {
    Request {
        method: Method::Get,
        url: url.to_owned(),
        headers: vec![("accept".to_owned(), "application/json".to_owned())],
        body: Vec::new(),
    }
}

/// `GET url` with `Authorization: Bearer token`.
pub(crate) fn get_bearer(url: &str, token: &str) -> Request {
    let mut request = get(url);
    request
        .headers
        .push(("authorization".to_owned(), format!("Bearer {token}")));
    request
}

/// `POST url` with a form body.
pub(crate) fn post_form(url: &str, fields: &[(&str, &str)]) -> Request {
    Request {
        method: Method::Post,
        url: url.to_owned(),
        headers: vec![
            (
                "content-type".to_owned(),
                "application/x-www-form-urlencoded".to_owned(),
            ),
            ("accept".to_owned(), "application/json".to_owned()),
        ],
        body: form(fields).into_bytes(),
    }
}

/// `Authorization: Basic` for OAuth client credentials: id and secret each
/// form-encoded before base64, as RFC 6749 §2.3.1 asks.
pub(crate) fn basic(client_id: &str, secret: &str) -> (String, String) {
    let pair = format!("{}:{}", encode(client_id), encode(secret));
    (
        "authorization".to_owned(),
        format!("Basic {}", Base64::encode_string(pair.as_bytes())),
    )
}

/// `application/x-www-form-urlencoded` of `fields`.
fn form(fields: &[(&str, &str)]) -> String {
    fields
        .iter()
        .map(|(name, value)| format!("{}={}", encode(name), encode(value)))
        .collect::<Vec<_>>()
        .join("&")
}

/// Form encoding: unreserved characters as they are, space as `+`, the rest as `%XX`.
fn encode(text: &str) -> String {
    use core::fmt::Write as _;
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(char::from(byte));
            }
            b' ' => out.push('+'),
            _ => {
                let _ = write!(out, "%{byte:02X}");
            }
        }
    }
    out
}

/// The directory's error document, or the bare status.
pub(crate) fn refusal(what: &'static str, response: &Response) -> Error {
    DirectoryError::from_body(response.status, &response.body).map_or_else(
        || Error::status(what, response.status, &response.body),
        Error::Directory,
    )
}

/// `scheme://host[:port]` of `url`, without a trailing slash.
pub(crate) fn origin(url: &str) -> &str {
    let after_scheme = url.find("://").map_or(0, |i| i + 3);
    let end = url[after_scheme..]
        .find(['/', '?', '#'])
        .map_or(url.len(), |i| after_scheme + i);
    &url[..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origins() {
        assert_eq!(
            origin("https://idp-ref.app.ti-dienste.de/auth?x=1"),
            "https://idp-ref.app.ti-dienste.de"
        );
        assert_eq!(origin("http://127.0.0.1:8085"), "http://127.0.0.1:8085");
        assert_eq!(origin("http://127.0.0.1:8085/"), "http://127.0.0.1:8085");
        assert_eq!(origin("idp.test/auth"), "idp.test");
    }

    #[test]
    fn forms_and_basic_credentials_are_encoded() {
        assert_eq!(
            form(&[("grant_type", "client_credentials"), ("x", "a b&c=d/é")]),
            "grant_type=client_credentials&x=a+b%26c%3Dd%2F%C3%A9"
        );
        // RFC 6749 §2.3.1: "a:b" as id must not be read as id "a", secret "b:…".
        let (_, value) = basic("a:b", "s p");
        let encoded = value.strip_prefix("Basic ").unwrap();
        assert_eq!(Base64::decode_vec(encoded).unwrap(), b"a%3Ab:s+p");
    }
}
