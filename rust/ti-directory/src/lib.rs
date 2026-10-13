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

//! The gematik FHIR-Directory (VZD-FHIR-Directory, gemSpec_VZD_FHIR_Directory V1.7.0) as
//! its clients see it: the token paths of its Auth-Service, each ending in an access
//! token (an ES256 JWT of the directory's) for its `/owner`, `/search`,
//! `/holder-services`, `/tim-provider-services` and `/certificates` endpoints.
//!
//! | [`Endpoint`] | Credential | Steps |
//! |---|---|---|
//! | `owner` | smartcard via the IDP-Dienst ([`owner::login`]) | `GET /owner-authenticate` redirects to the IDP-Dienst; the Authenticator-Modul flow of [`ti_idpd`] yields a code for `/signin-gematik-idp-dienst`, which answers with the token |
//! | `owner` | a TI-Messenger RegService-OpenID-Token ([`exchange::login_bearer`]) | `GET /owner-authenticate` with it as bearer |
//! | `holder`, `service`, `ti-provider` | client credentials at the directory's Keycloak ([`exchange::login_client_credentials`]) | a Keycloak token from the endpoint's realm, exchanged at `/holder-authenticate`, `/service-authenticate` or `/ti-provider-authenticate` |
//!
//! The directory is the relying party of the IDP-Dienst and keeps the OpenID state;
//! for a card the client is only the Authenticator-Modul, as it is for ePA. The core is
//! sans I/O: the steps build [`http::Request`]s and consume [`http::Response`]s, the
//! `login` functions run them over a [`http::Transport`]. Not implemented:
//! `/tim-authenticate` (a Matrix OpenID token) and the decoupled variant for the gematik
//! Authenticator app (this tool is the Authenticator-Modul itself: `ti idpd`).

#![forbid(unsafe_code)]

mod error;
pub mod exchange;
pub mod keycloak;
pub mod owner;
pub(crate) mod request;
pub mod token;

pub use error::{AttributeError, DirectoryError, Error, OAuthError};
pub use ti_idpd::http;
pub use ti_idpd::{Env, Idp};
pub use token::{AccessToken, TokenClaims};

/// A FHIR-Directory, the IDP-Dienst it authenticates owners with, and the Keycloak
/// that issues the tokens of its client-credentials paths.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Directory {
    base_url: String,
    idp: Idp,
    auth_url: Option<String>,
}

impl Directory {
    /// The directory at `base_url` (scheme and host, no trailing slash needed), which
    /// must redirect to `idp` and no other; without a Keycloak until
    /// [`with_auth_url`](Self::with_auth_url).
    pub fn new(base_url: &str, idp: Idp) -> Directory {
        Directory {
            base_url: base_url.trim_end_matches('/').to_owned(),
            idp,
            auth_url: None,
        }
    }

    /// gematik's FHIR-Directory of `env` with the environment's IDP-Dienst and
    /// Keycloak: production, test (TU) or reference (also for development). TU's
    /// Keycloak is `auth-test`, its directory `fhir-directory-tu`.
    pub fn for_env(env: Env) -> Directory {
        let (directory, auth) = match env {
            Env::Prod => (
                "https://fhir-directory.vzd.ti-dienste.de",
                "https://auth.vzd.ti-dienste.de:9443",
            ),
            Env::Test => (
                "https://fhir-directory-tu.vzd.ti-dienste.de",
                "https://auth-test.vzd.ti-dienste.de:9443",
            ),
            _ => (
                "https://fhir-directory-ref.vzd.ti-dienste.de",
                "https://auth-ref.vzd.ti-dienste.de:9443",
            ),
        };
        Directory::new(directory, Idp::for_env(env)).with_auth_url(auth)
    }

    /// The directory with its Keycloak at `auth_url` (scheme, host and port).
    #[must_use]
    pub fn with_auth_url(mut self, auth_url: &str) -> Directory {
        self.auth_url = Some(auth_url.trim_end_matches('/').to_owned());
        self
    }

    /// The Keycloak base URL, if known.
    pub fn auth_url(&self) -> Option<&str> {
        self.auth_url.as_deref()
    }

    /// The base URL.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// The IDP-Dienst the directory may send the client to.
    pub fn idp(&self) -> &Idp {
        &self.idp
    }

    /// The URL of `endpoint`'s token exchange at this directory.
    pub fn endpoint_url(&self, endpoint: Endpoint) -> String {
        format!("{}{}", self.base_url, endpoint.path())
    }
}

/// An Auth-Service endpoint that issues a directory token: what the token's `iss`
/// names.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Endpoint {
    /// `/owner-authenticate`: organisations and practitioners for their own entries.
    Owner,
    /// `/holder-authenticate`: registration services administering entries.
    Holder,
    /// `/service-authenticate`: Fachdienste and FdV providers, for search.
    Service,
    /// `/ti-provider-authenticate`: TI-Messenger providers, for the provider services.
    TiProvider,
}

impl Endpoint {
    /// The name the CLI and reports use: `owner`, `holder`, `service`, `ti-provider`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Endpoint::Owner => "owner",
            Endpoint::Holder => "holder",
            Endpoint::Service => "service",
            Endpoint::TiProvider => "ti-provider",
        }
    }

    /// The path at the directory.
    pub const fn path(self) -> &'static str {
        match self {
            Endpoint::Owner => "/owner-authenticate",
            Endpoint::Holder => "/holder-authenticate",
            Endpoint::Service => "/service-authenticate",
            Endpoint::TiProvider => "/ti-provider-authenticate",
        }
    }

    /// The Keycloak realm whose client-credentials token the endpoint exchanges; none
    /// for `owner`, which takes a card or a RegService-OpenID-Token.
    pub const fn realm(self) -> Option<&'static str> {
        match self {
            Endpoint::Owner => None,
            Endpoint::Holder => Some("RSDirectoryAdministration"),
            Endpoint::Service => Some("Service-Authenticate"),
            Endpoint::TiProvider => Some("TI-Provider"),
        }
    }
}
