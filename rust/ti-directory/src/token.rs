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

//! The directory's access token, the same document on every path.

use base64ct::{Base64UrlUnpadded, Encoding};
use serde::{Deserialize, Deserializer, Serialize};
use ti_idpd::http::Response;

use crate::error::Error;
use crate::request::refusal;

/// An access token as the directory issued it.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct AccessToken {
    /// The bearer token: an ES256 JWT of the directory's.
    pub access_token: String,
    /// `Bearer` (spelled `bearer` by some endpoints).
    pub token_type: String,
    /// Seconds until it expires, as announced.
    pub expires_in: u64,
    /// The token's payload, decoded for the record. The signature is the directory's
    /// own and is not verified here: the token arrived from the directory itself.
    #[serde(skip)]
    pub claims: TokenClaims,
}

/// The claims of a directory access token (gemSpec_VZD_FHIR_Directory, "Das
/// Accesstoken enthält folgende Attribute"). Every member is optional so that a token
/// shaped differently is still a token.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct TokenClaims {
    /// The endpoint that issued it, e.g. `{directory}/owner-authenticate`.
    #[serde(default)]
    pub iss: Option<String>,
    /// The Telematik-ID for an owner, the client ID for client credentials.
    #[serde(default)]
    pub sub: Option<String>,
    /// The directory endpoints the token is for.
    #[serde(default, deserialize_with = "audience")]
    pub aud: Vec<String>,
    /// `owner:read owner:write search:read …`.
    #[serde(default)]
    pub scope: Option<String>,
    /// Issued at, seconds since the epoch.
    #[serde(default)]
    pub iat: Option<u64>,
    /// Expires at, seconds since the epoch.
    #[serde(default)]
    pub exp: Option<u64>,
}

/// The token in `response`, which answers a request of step `what`.
///
/// # Errors
///
/// [`Error::Directory`] when the directory refused; [`Error::Status`] for another
/// status; [`Error::Malformed`] when the document or the token is not what the
/// specification says.
pub fn parse(what: &'static str, response: &Response) -> Result<AccessToken, Error> {
    if response.status != 200 {
        return Err(refusal(what, response));
    }
    let mut token: AccessToken = serde_json::from_slice(&response.body)
        .map_err(|e| Error::malformed(what, format!("token document: {e}")))?;
    if token.access_token.is_empty() {
        return Err(Error::malformed(what, "empty access_token"));
    }
    token.claims = claims(&token.access_token)
        .ok_or_else(|| Error::malformed(what, "access_token is not a JWT"))?;
    Ok(token)
}

/// `aud` as a string or an array of strings (RFC 7519 §4.1.3).
fn audience<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<String>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Audience {
        One(String),
        Many(Vec<String>),
    }
    Ok(match Option::<Audience>::deserialize(deserializer)? {
        None => Vec::new(),
        Some(Audience::One(one)) => vec![one],
        Some(Audience::Many(many)) => many,
    })
}

/// The payload of a compact JWS, when `token` is one.
fn claims(token: &str) -> Option<TokenClaims> {
    let mut parts = token.split('.');
    let (_, payload, _) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() {
        return None;
    }
    serde_json::from_slice(&Base64UrlUnpadded::decode_vec(payload).ok()?).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audience_takes_a_string_or_an_array() {
        let one: TokenClaims = serde_json::from_str(r#"{"aud":"a"}"#).unwrap();
        assert_eq!(one.aud, ["a"]);
        let many: TokenClaims = serde_json::from_str(r#"{"aud":["a","b"]}"#).unwrap();
        assert_eq!(many.aud, ["a", "b"]);
        let none: TokenClaims = serde_json::from_str("{}").unwrap();
        assert!(none.aud.is_empty(), "{:?}", none.aud);
    }
}
