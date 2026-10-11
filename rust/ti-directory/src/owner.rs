//! Owner authentication: from `GET /owner-authenticate` to the owner access token.

use base64ct::{Base64UrlUnpadded, Encoding};
use serde::{Deserialize, Deserializer, Serialize};
use ti_idpd::authenticator::{self, Authenticated, Identity};
use ti_idpd::challenge::CodeRedirect;
use ti_idpd::http::{Method, Request, Response, Transport};
use ti_idpd::trust::CertificateTrust;

use crate::Directory;
use crate::error::{DirectoryError, Error};

/// The endpoint that starts the authentication (and issues the token to a client that
/// already holds one).
pub const AUTHENTICATE_PATH: &str = "/owner-authenticate";
/// The endpoint the IDP-Dienst redirects to with the code, which answers with the token.
pub const SIGN_IN_PATH: &str = "/signin-gematik-idp-dienst";

/// The owner access token as the directory issued it.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct OwnerToken {
    /// The bearer token: an ES256 JWT of the directory's.
    pub access_token: String,
    /// `Bearer`.
    pub token_type: String,
    /// Seconds until it expires, as announced; 24 hours by specification.
    pub expires_in: u64,
    /// The token's payload, decoded for the record. The signature is the directory's
    /// own and is not verified here: the token arrived from the directory itself.
    #[serde(skip)]
    pub claims: TokenClaims,
}

/// The claims of an owner access token (gemSpec_VZD_FHIR_Directory, "Das Accesstoken
/// enthält folgende Attribute"). Every member is optional so that a token shaped
/// differently is still a token.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct TokenClaims {
    /// `{directory}/owner-authenticate`.
    #[serde(default)]
    pub iss: Option<String>,
    /// The Telematik-ID.
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

/// What a login yielded.
#[derive(Clone, Debug)]
pub struct Login {
    /// The token.
    pub token: OwnerToken,
    /// The authorization URL the directory sent the client to.
    pub authorization_url: String,
    /// The IDP-Dienst flow's result: discovery document, challenge claims, warnings.
    pub authenticated: Authenticated,
}

/// The first request: `GET {directory}/owner-authenticate`, not following redirects.
pub fn start(directory: &Directory) -> Request {
    get(&format!("{}{AUTHENTICATE_PATH}", directory.base_url()))
}

/// The IDP-Dienst authorization URL in the `302` that answers [`start`]'s request.
///
/// # Errors
///
/// [`Error::Directory`] when the directory refused; [`Error::Status`] for a status
/// that is not a redirect; [`Error::Malformed`] for a redirect without `Location`, or
/// to a host other than the directory's IDP-Dienst — the identity signs challenges
/// for that IDP only.
pub fn authorization_url(directory: &Directory, response: &Response) -> Result<String, Error> {
    const WHAT: &str = "owner-authenticate";
    if !(300..400).contains(&response.status) {
        return Err(refusal(WHAT, response));
    }
    let location = response
        .header("location")
        .ok_or_else(|| Error::malformed(WHAT, "no Location"))?;
    let expected = directory.idp().base_url();
    if !origin(location).eq_ignore_ascii_case(origin(expected)) {
        return Err(Error::malformed(
            WHAT,
            format!("redirects to {location}, not to the IDP-Dienst at {expected}"),
        ));
    }
    Ok(location.to_owned())
}

/// The request that exchanges the IDP's redirect for the token: `GET` the redirect, which
/// must be the directory's sign-in endpoint.
///
/// # Errors
///
/// [`Error::Malformed`] when the IDP's redirect does not go to
/// `{directory}/signin-gematik-idp-dienst`: the code is the directory's and goes
/// nowhere else.
pub fn sign_in(directory: &Directory, redirect: &CodeRedirect) -> Result<Request, Error> {
    let expected = format!("{}{SIGN_IN_PATH}", directory.base_url());
    let (endpoint, _) = redirect.url.split_once('?').unwrap_or((&redirect.url, ""));
    if !endpoint.eq_ignore_ascii_case(&expected) {
        return Err(Error::malformed(
            "code redirect",
            format!("the IDP redirects to {endpoint}, not to {expected}"),
        ));
    }
    Ok(get(&redirect.url))
}

/// The token in the response to [`sign_in`]'s request.
///
/// # Errors
///
/// [`Error::Directory`] when the directory refused; [`Error::Status`] for another
/// status; [`Error::Malformed`] when the document or the token is not what the
/// specification says.
pub fn token(response: &Response) -> Result<OwnerToken, Error> {
    const WHAT: &str = "signin-gematik-idp-dienst";
    if response.status != 200 {
        return Err(refusal(WHAT, response));
    }
    let mut token: OwnerToken = serde_json::from_slice(&response.body)
        .map_err(|e| Error::malformed(WHAT, format!("token document: {e}")))?;
    if token.access_token.is_empty() {
        return Err(Error::malformed(WHAT, "empty access_token"));
    }
    token.claims = claims(&token.access_token)
        .ok_or_else(|| Error::malformed(WHAT, "access_token is not a JWT"))?;
    Ok(token)
}

/// The whole authentication over `transport`: the directory's redirect, the IDP-Dienst
/// flow with `identity`, the token; `now` is seconds since the epoch, for the IDP's
/// token validity; `trust` decides about the IDP's certificates.
///
/// # Errors
///
/// The first failing step's [`Error`].
pub fn login<T: Transport>(
    transport: &T,
    directory: &Directory,
    identity: &Identity<'_>,
    now: u64,
    trust: &dyn CertificateTrust,
) -> Result<Login, Error> {
    let send = |what: &'static str, request: &Request| {
        transport
            .send(request)
            .map_err(|source| Error::Transport { what, source })
    };
    let authorization_url =
        authorization_url(directory, &send("owner-authenticate", &start(directory))?)?;
    let authenticated = authenticator::authenticate(
        transport,
        directory.idp(),
        identity,
        &authorization_url,
        now,
        trust,
    )?;
    let request = sign_in(directory, &authenticated.redirect)?;
    let token = token(&send("signin-gematik-idp-dienst", &request)?)?;
    Ok(Login {
        token,
        authorization_url,
        authenticated,
    })
}

fn get(url: &str) -> Request {
    Request {
        method: Method::Get,
        url: url.to_owned(),
        headers: vec![("accept".to_owned(), "application/json".to_owned())],
        body: Vec::new(),
    }
}

/// The directory's error document, or the bare status.
fn refusal(what: &'static str, response: &Response) -> Error {
    DirectoryError::from_body(response.status, &response.body).map_or_else(
        || Error::status(what, response.status, &response.body),
        Error::Directory,
    )
}

/// `scheme://host[:port]` of `url`, without a trailing slash.
fn origin(url: &str) -> &str {
    let after_scheme = url.find("://").map_or(0, |i| i + 3);
    let end = url[after_scheme..]
        .find(['/', '?', '#'])
        .map_or(url.len(), |i| after_scheme + i);
    &url[..end]
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
    fn audience_takes_a_string_or_an_array() {
        let one: TokenClaims = serde_json::from_str(r#"{"aud":"a"}"#).unwrap();
        assert_eq!(one.aud, ["a"]);
        let many: TokenClaims = serde_json::from_str(r#"{"aud":["a","b"]}"#).unwrap();
        assert_eq!(many.aud, ["a", "b"]);
        let none: TokenClaims = serde_json::from_str("{}").unwrap();
        assert!(none.aud.is_empty());
    }
}
