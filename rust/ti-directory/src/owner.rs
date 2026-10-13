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

//! The owner path by card: the directory sends the client to the IDP-Dienst, whose code
//! it exchanges for the owner token.

use ti_idpd::authenticator::{self, Authenticated, Identity};
use ti_idpd::challenge::CodeRedirect;
use ti_idpd::http::{Request, Response, Transport};
use ti_idpd::trust::CertificateTrust;

use crate::error::Error;
use crate::request::{get, origin, refusal};
use crate::token::{self, AccessToken};
use crate::{Directory, Endpoint};

/// The endpoint the IDP-Dienst redirects to with the code, which answers with the token.
pub const SIGN_IN_PATH: &str = "/signin-gematik-idp-dienst";

/// What a login by card yielded.
#[derive(Clone, Debug)]
pub struct Login {
    /// The token.
    pub token: AccessToken,
    /// The authorization URL the directory sent the client to.
    pub authorization_url: String,
    /// The IDP-Dienst flow's result: discovery document, challenge claims, warnings.
    pub authenticated: Authenticated,
}

/// The first request: `GET {directory}/owner-authenticate`, not following redirects.
pub fn start(directory: &Directory) -> Request {
    get(&directory.endpoint_url(Endpoint::Owner))
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
    to_own_idp(WHAT, directory, location)?;
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
    redirect_to(directory, redirect, SIGN_IN_PATH)
}

/// The token in the response to [`sign_in`]'s request.
///
/// # Errors
///
/// As [`token::parse`].
pub fn token(response: &Response) -> Result<AccessToken, Error> {
    token::parse("signin-gematik-idp-dienst", response)
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

/// `url` must be at the directory's IDP-Dienst: the identity signs for that IDP only.
fn to_own_idp(what: &'static str, directory: &Directory, url: &str) -> Result<(), Error> {
    let expected = directory.idp().base_url();
    if origin(url).eq_ignore_ascii_case(origin(expected)) {
        Ok(())
    } else {
        Err(Error::malformed(
            what,
            format!("redirects to {url}, not to the IDP-Dienst at {expected}"),
        ))
    }
}

/// `GET` the IDP's redirect, which must be the directory's `path`.
fn redirect_to(
    directory: &Directory,
    redirect: &CodeRedirect,
    path: &str,
) -> Result<Request, Error> {
    let expected = format!("{}{path}", directory.base_url());
    let (endpoint, _) = redirect.url.split_once('?').unwrap_or((&redirect.url, ""));
    if !endpoint.eq_ignore_ascii_case(&expected) {
        return Err(Error::malformed(
            "code redirect",
            format!("the IDP redirects to {endpoint}, not to {expected}"),
        ));
    }
    Ok(get(&redirect.url))
}
