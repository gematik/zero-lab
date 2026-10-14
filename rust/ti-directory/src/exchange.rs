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
