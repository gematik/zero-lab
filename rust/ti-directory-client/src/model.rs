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

//! The response model: read-only projections of a directory login as the front ends show
//! it. The types only map: no I/O, no request, no clock of their own; the instant a
//! token's expiry is reckoned from comes from the caller. With the `serde` feature they
//! serialize to the JSON the `ti` CLI publishes, which its schema
//! (`ti-cli/schemas/directory-login.json`) describes; the shape is declared here, the
//! format is the host's.

use ti_types::Timestamp;

use crate::token::{AccessToken, TokenClaims};
use crate::{Directory, Endpoint, Warning};

/// How the token was had.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Credential {
    /// A smartcard through the IDP-Dienst.
    Card,
    /// A TI-Messenger RegService-OpenID-Token.
    RegService,
    /// Client credentials at the directory's Keycloak.
    ClientCredentials,
}

impl Credential {
    /// The stable name: `card`, `regservice`, `client_credentials`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Credential::Card => "card",
            Credential::RegService => "regservice",
            Credential::ClientCredentials => "client_credentials",
        }
    }
}

/// An access token the directory issued, and where.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Token {
    /// `owner`, `holder`, `service` or `ti-provider` ([`Endpoint::as_str`]).
    pub endpoint: &'static str,
    /// `card`, `regservice` or `client_credentials` ([`Credential::as_str`]).
    pub method: &'static str,
    /// The access token, for `Authorization: Bearer`.
    pub access_token: String,
    /// `Bearer`, as the endpoint spelled it.
    pub token_type: String,
    /// Seconds of validity, as announced.
    pub expires_in: u64,
    /// When it expires, seconds since the epoch, from the caller's clock and `expires_in`.
    pub expires_at: u64,
    /// The token's payload as decoded, not verified: the directory issued it over TLS.
    pub token: TokenClaims,
    /// Where it was issued.
    pub directory: DirectoryInfo,
}

/// The directory a token came from.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[allow(
    clippy::struct_field_names,
    reason = "the field names are the JSON contract"
)]
pub struct DirectoryInfo {
    /// The directory's base URL.
    pub base_url: String,
    /// The endpoint that issued the token.
    pub endpoint_url: String,
    /// The IDP-Dienst authorization URL the directory sent the card to; none without
    /// a card.
    pub authorization_url: Option<String>,
    /// The Search API the token is for; none unless it was had for the search.
    pub search_url: Option<String>,
}

impl Token {
    /// `token`, issued by `directory`'s `endpoint` for `credential`, read at `now`.
    pub fn new(
        directory: &Directory,
        endpoint: Endpoint,
        credential: Credential,
        token: AccessToken,
        now: Timestamp,
    ) -> Token {
        Token {
            endpoint: endpoint.as_str(),
            method: credential.as_str(),
            expires_at: now.0.saturating_add(token.expires_in),
            access_token: token.access_token,
            token_type: token.token_type,
            expires_in: token.expires_in,
            token: token.claims,
            directory: DirectoryInfo {
                base_url: directory.base_url().to_owned(),
                endpoint_url: directory.endpoint_url(endpoint),
                authorization_url: None,
                search_url: None,
            },
        }
    }

    /// The token as one for `directory`'s Search API, which the owner token of a card
    /// opens: [`Warning::SearchNotInAudience`] when its `aud` does not name it.
    pub fn for_search(&mut self, directory: &Directory) -> Option<Warning> {
        let search_url = directory.search_url();
        let named = self.token.aud.contains(&search_url);
        self.directory.search_url = Some(search_url);
        (!named).then_some(Warning::SearchNotInAudience)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owner_token(aud: &[&str]) -> AccessToken {
        AccessToken {
            access_token: "a.b.c".to_owned(),
            token_type: "Bearer".to_owned(),
            expires_in: 300,
            claims: TokenClaims {
                aud: aud.iter().map(|a| (*a).to_owned()).collect(),
                ..TokenClaims::default()
            },
        }
    }

    #[test]
    fn a_token_expires_its_validity_after_the_callers_instant() {
        let directory = Directory::new("https://directory.test/", "https://idp.test");
        let token = Token::new(
            &directory,
            Endpoint::Owner,
            Credential::Card,
            owner_token(&[]),
            Timestamp(1_000),
        );
        assert_eq!((token.endpoint, token.method), ("owner", "card"));
        assert_eq!(token.expires_at, 1_300);
        assert_eq!(
            token.directory.endpoint_url,
            "https://directory.test/owner-authenticate"
        );
        assert_eq!(token.directory.search_url, None);
    }

    #[test]
    fn a_token_for_the_search_names_the_search_api_in_its_audience() {
        let directory = Directory::new("https://directory.test", "https://idp.test");
        let mut token = Token::new(
            &directory,
            Endpoint::Owner,
            Credential::Card,
            owner_token(&[
                "https://directory.test/owner",
                "https://directory.test/search",
            ]),
            Timestamp(0),
        );
        assert_eq!(token.for_search(&directory), None);
        assert_eq!(
            token.directory.search_url.as_deref(),
            Some("https://directory.test/search")
        );
        let mut token = Token::new(
            &directory,
            Endpoint::Owner,
            Credential::Card,
            owner_token(&["https://directory.test/owner"]),
            Timestamp(0),
        );
        assert_eq!(
            token.for_search(&directory),
            Some(Warning::SearchNotInAudience)
        );
    }
}
