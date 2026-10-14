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

//! The client-credentials step: a token from the directory's Keycloak, realm by
//! endpoint, which the endpoint then exchanges for a directory token.

use serde::Deserialize;
use ti_idpd::http::{Request, Response};

use crate::error::{Error, OAuthError};
use crate::request::{basic, post_form};
use crate::{Directory, Endpoint};

/// What Keycloak issued: short-lived, only good for the exchange.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct KeycloakToken {
    /// The bearer for the exchange.
    pub access_token: String,
    /// Seconds of validity; five minutes for `TI-Provider`.
    #[serde(default)]
    pub expires_in: Option<u64>,
}

/// `POST {auth}/auth/realms/{realm}/protocol/openid-connect/token` with
/// `grant_type=client_credentials`, the client authenticated by `Basic`.
///
/// # Errors
///
/// [`Error::NoAuthUrl`] without a Keycloak URL; [`Error::Malformed`] for an endpoint
/// without a realm (`owner`).
pub fn token_request(
    directory: &Directory,
    endpoint: Endpoint,
    client_id: &str,
    client_secret: &str,
) -> Result<Request, Error> {
    let realm = endpoint.realm().ok_or_else(|| {
        Error::malformed(
            "client credentials",
            format!(
                "the {} endpoint takes no client credentials",
                endpoint.as_str()
            ),
        )
    })?;
    let auth = directory
        .auth_url()
        .ok_or(Error::NoAuthUrl(endpoint.as_str()))?;
    let mut request = post_form(
        &format!("{auth}/auth/realms/{realm}/protocol/openid-connect/token"),
        &[("grant_type", "client_credentials")],
    );
    request.headers.push(basic(client_id, client_secret));
    Ok(request)
}

/// The Keycloak token in `response`.
///
/// # Errors
///
/// [`Error::AuthServer`] for Keycloak's OAuth error (`invalid_client`,
/// `unauthorized_client`, …); [`Error::Status`] for another failure;
/// [`Error::Malformed`] for a document without `access_token`.
pub fn token(response: &Response) -> Result<KeycloakToken, Error> {
    const WHAT: &str = "Keycloak token";
    if response.status != 200 {
        return Err(
            OAuthError::from_body(response.status, &response.body).map_or_else(
                || Error::status(WHAT, response.status, &response.body),
                Error::AuthServer,
            ),
        );
    }
    let token: KeycloakToken = serde_json::from_slice(&response.body)
        .map_err(|e| Error::malformed(WHAT, format!("token document: {e}")))?;
    if token.access_token.is_empty() {
        return Err(Error::malformed(WHAT, "empty access_token"));
    }
    Ok(token)
}
