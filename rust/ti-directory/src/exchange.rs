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

//! The bearer exchange: `GET {directory}/{endpoint}-authenticate` with a token the
//! endpoint accepts, answered by the directory's own token.

use ti_idpd::http::{Request, Transport};

use crate::error::Error;
use crate::token::{self, AccessToken};
use crate::{Directory, Endpoint, keycloak};

/// `GET` `endpoint` with `bearer`: a Keycloak token for `holder`, `service` and
/// `ti-provider`, a TI-Messenger RegService-OpenID-Token for `owner`.
pub fn request(directory: &Directory, endpoint: Endpoint, bearer: &str) -> Request {
    crate::request::get_bearer(&directory.endpoint_url(endpoint), bearer)
}

/// A directory token for `bearer` at `endpoint`.
///
/// # Errors
///
/// [`Error::Transport`] when the directory does not answer, else as
/// [`token::parse`].
pub fn login_bearer<T: Transport>(
    transport: &T,
    directory: &Directory,
    endpoint: Endpoint,
    bearer: &str,
) -> Result<AccessToken, Error> {
    let what: &'static str = match endpoint {
        Endpoint::Owner => "owner-authenticate",
        Endpoint::Holder => "holder-authenticate",
        Endpoint::Service => "service-authenticate",
        Endpoint::TiProvider => "ti-provider-authenticate",
    };
    debug_assert_eq!(what, endpoint.path().trim_start_matches('/'));
    let response = transport
        .send(&request(directory, endpoint, bearer))
        .map_err(|source| Error::Transport { what, source })?;
    token::parse(what, &response)
}

/// A directory token with client credentials: Keycloak's token from `endpoint`'s
/// realm, exchanged at `endpoint`.
///
/// # Errors
///
/// [`Error::AuthServer`] when Keycloak refuses the credentials, else the first failing
/// step's [`Error`].
pub fn login_client_credentials<T: Transport>(
    transport: &T,
    directory: &Directory,
    endpoint: Endpoint,
    client_id: &str,
    client_secret: &str,
) -> Result<AccessToken, Error> {
    let request = keycloak::token_request(directory, endpoint, client_id, client_secret)?;
    let response = transport
        .send(&request)
        .map_err(|source| Error::Transport {
            what: "Keycloak token",
            source,
        })?;
    let keycloak = keycloak::token(&response)?;
    login_bearer(transport, directory, endpoint, &keycloak.access_token)
}
