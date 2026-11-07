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

//! The owner path by card: the directory sends the client to the IDP-Dienst, whose code
//! it exchanges for the owner token.
//!
//! Between [`authorization_url`] and [`sign_in`] runs the IDP-Dienst's Authenticator-Modul
//! flow, another product's: the host hands the authorization URL to its IDP-Dienst client
//! and the redirect with the code back here. The guards stay on this side: the
//! authorization URL must be the directory's own IDP-Dienst, and the code goes to the
//! directory's sign-in endpoint only.

use crate::error::Error;
use crate::http::{Request, Response};
use crate::request::{get, origin, refusal};
use crate::token::{self, AccessToken};
use crate::{Directory, Endpoint};

/// The endpoint the IDP-Dienst redirects to with the code, which answers with the token.
pub const SIGN_IN_PATH: &str = "/signin-gematik-idp-dienst";

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

/// The request that exchanges the IDP's redirect for the token: `GET` `redirect_url`, the
/// `Location` the IDP-Dienst answered the signed challenge with, which must be the
/// directory's sign-in endpoint.
///
/// # Errors
///
/// [`Error::Malformed`] when the IDP's redirect does not go to
/// `{directory}/signin-gematik-idp-dienst`: the code is the directory's and goes
/// nowhere else.
pub fn sign_in(directory: &Directory, redirect_url: &str) -> Result<Request, Error> {
    let expected = format!("{}{SIGN_IN_PATH}", directory.base_url());
    let (endpoint, _) = redirect_url.split_once('?').unwrap_or((redirect_url, ""));
    if !endpoint.eq_ignore_ascii_case(&expected) {
        return Err(Error::malformed(
            "code redirect",
            format!("the IDP redirects to {endpoint}, not to {expected}"),
        ));
    }
    Ok(get(redirect_url))
}

/// The token in the response to [`sign_in`]'s request.
///
/// # Errors
///
/// As [`token::parse`].
pub fn token(response: &Response) -> Result<AccessToken, Error> {
    token::parse("signin-gematik-idp-dienst", response)
}

/// `url` must be at the directory's IDP-Dienst: the identity signs for that IDP only.
fn to_own_idp(what: &'static str, directory: &Directory, url: &str) -> Result<(), Error> {
    let expected = directory.idp_url();
    if origin(url).eq_ignore_ascii_case(origin(expected)) {
        Ok(())
    } else {
        Err(Error::malformed(
            what,
            format!("redirects to {url}, not to the IDP-Dienst at {expected}"),
        ))
    }
}
