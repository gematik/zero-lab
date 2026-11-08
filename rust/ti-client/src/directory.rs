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

//! A FHIR-Directory access token from one of its Auth-Service endpoints: by card through
//! the IDP-Dienst ([`owner`]), with a TI-Messenger RegService-OpenID-Token, or with client
//! credentials at the directory's Keycloak.

use core::fmt;

use serde::Serialize;
use ti_directory_client::model::{Credential, Token};
use ti_directory_client::{Directory, Endpoint, exchange};
use ti_idpd_client::model::{CertificateInfo, ChallengeInfo as Challenge};
use ti_pki::Timestamp;

use crate::block_on;
use crate::error::Error;
use crate::idp_trust::IdpTrust;
use crate::idpd::{Card, IdentityInfo, idpd_error, warnings};

pub mod owner;

pub use owner::{ByCard, Issued, OwnerError, OwnerTokens};

/// A login's result, whichever the path.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Login {
    /// The token and where it was issued.
    #[serde(flatten)]
    pub token: Token,
    /// The IDP-Dienst a card answered; none for the other methods.
    pub idp: Option<IdpInfo>,
    /// The card identity; none without one.
    pub identity: Option<IdentityInfo>,
    /// Claims of the IDP's challenge, for the record; `client_id` is the directory's.
    pub challenge: Option<ChallengeInfo>,
    /// The client ID of client credentials; none for the owner methods.
    pub client_id: Option<String>,
    /// What was not proven: `idp_certificates_unverified` without a check of the IDP's
    /// certificates; `search_not_in_audience` when a token for search does not name
    /// `/search`.
    pub warnings: Vec<&'static str>,
}

/// The IDP-Dienst a card login went through.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct IdpInfo {
    /// The directory's IDP-Dienst.
    pub base_url: String,
    /// `issuer` of its discovery document.
    pub issuer: String,
    /// The discovery document's and `PuK_IDP_SIG`'s certificates.
    pub certificates: Vec<CertificateInfo>,
}

/// What the directory, as the IDP's relying party, asked for.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ChallengeInfo {
    /// The directory's `client_id` at the IDP.
    pub client_id: Option<String>,
    /// `scope`.
    pub scope: Option<String>,
}

impl Login {
    fn new(token: Token) -> Login {
        Login {
            token,
            idp: None,
            identity: None,
            challenge: None,
            client_id: None,
            warnings: Vec::new(),
        }
    }
}

/// The token of `endpoint` (`holder`, `service`, `ti-provider`) for the client
/// credentials `client_id` and `secret`, through the directory's Keycloak.
///
/// # Errors
///
/// [`Error::Directory`].
pub fn client_credentials<T: ti_directory_client::http::Transport>(
    transport: &T,
    directory: &Directory,
    endpoint: Endpoint,
    client_id: &str,
    secret: &str,
) -> Result<Login, Error> {
    let token = block_on(exchange::login_client_credentials(
        transport, directory, endpoint, client_id, secret,
    ))
    .map_err(directory_error)?;
    let mut login = Login::new(Token::new(
        directory,
        endpoint,
        Credential::ClientCredentials,
        token,
        Timestamp::now(),
    ));
    login.client_id = Some(client_id.to_owned());
    Ok(login)
}

/// The owner token for a TI-Messenger RegService-OpenID-Token, `bearer`.
///
/// # Errors
///
/// [`Error::Directory`].
pub fn regservice<T: ti_directory_client::http::Transport>(
    transport: &T,
    directory: &Directory,
    bearer: &str,
) -> Result<Login, Error> {
    let token = block_on(exchange::login_bearer(
        transport,
        directory,
        Endpoint::Owner,
        bearer,
    ))
    .map_err(directory_error)?;
    Ok(Login::new(Token::new(
        directory,
        Endpoint::Owner,
        Credential::RegService,
        token,
        Timestamp::now(),
    )))
}

/// The owner token of `card`, through the directory's IDP-Dienst, its certificates
/// judged by `trust`.
///
/// # Errors
///
/// [`Error::Directory`] for the directory's steps; for the IDP-Dienst's, the front end's
/// error for trust material that could not be loaded, which a refusal of the IDP's
/// certificates stands for, and [`Error::Idpd`] otherwise.
pub fn card<T, E>(
    transport: &T,
    directory: &Directory,
    card: &Card<'_>,
    trust: &IdpTrust<'_, E>,
) -> Result<Login, E>
where
    T: ti_directory_client::http::Transport + ti_idpd_client::http::Transport,
    E: From<Error> + fmt::Display,
{
    let identity = card.authenticator();
    let tokens = OwnerTokens::new(
        async || owner::login(transport, directory, &identity, Timestamp::now, trust).await,
        Timestamp::now,
    );
    let issued = block_on(tokens.issued()).map_err(|error| match error {
        OwnerError::Directory(error) => directory_error(error).into(),
        OwnerError::Idpd(error) => idpd_error(trust, error),
    })?;
    let authenticated = &issued.how.authenticated;
    let idp = ti_idpd_client::model::IdpInfo::new(
        &ti_idpd_client::Idp::new(directory.idp_url()),
        authenticated,
    );
    let challenge = Challenge::from(authenticated);
    let mut login = Login::new(Token::new(
        directory,
        Endpoint::Owner,
        Credential::Card,
        issued.token,
        Timestamp::now(),
    ));
    login.token.directory.authorization_url = Some(issued.how.authorization_url);
    login.idp = Some(IdpInfo {
        base_url: idp.base_url,
        issuer: idp.issuer,
        certificates: idp.certificates,
    });
    login.identity = Some(card.info());
    login.challenge = Some(ChallengeInfo {
        client_id: challenge.client_id,
        scope: challenge.scope,
    });
    login.warnings = warnings(authenticated);
    Ok(login)
}

/// The owner token of `card` for the directory's Search API, as [`card`] has it.
///
/// # Errors
///
/// As [`card`].
pub fn search<T, E>(
    transport: &T,
    directory: &Directory,
    card: &Card<'_>,
    trust: &IdpTrust<'_, E>,
) -> Result<Login, E>
where
    T: ti_directory_client::http::Transport + ti_idpd_client::http::Transport,
    E: From<Error> + fmt::Display,
{
    let mut login = self::card(transport, directory, card, trust)?;
    if let Some(warning) = login.token.for_search(directory) {
        login.warnings.push(warning.as_str());
    }
    Ok(login)
}

fn directory_error(error: ti_directory_client::Error) -> Error {
    Error::Directory(Box::new(error))
}
