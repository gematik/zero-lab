//! The gematik FHIR-Directory (VZD-FHIR-Directory, gemSpec_VZD_FHIR_Directory V1.7.0) as
//! an organisation's or practitioner's client sees it: the owner authentication that
//! turns a smartcard identity (SMC-B, HBA) into an owner access token for the
//! `/owner` and `/search` endpoints.
//!
//! The directory is the relying party of the IDP-Dienst and keeps the OpenID state;
//! the client is only the Authenticator-Modul, as it is for ePA:
//!
//! 1. `GET {directory}/owner-authenticate` without a token: `302` to the IDP-Dienst's
//!    authorization URL (`client_id`, `scope`, `redirect_uri`, `state`, PKCE), which is
//!    the directory's business and is passed on as is.
//! 2. The Authenticator-Modul flow of [`ti_idpd`] against that URL; the IDP's `302`
//!    goes to `{directory}/signin-gematik-idp-dienst?code=…&state=…`.
//! 3. `GET` that redirect: `200` with `{access_token, token_type, expires_in}`, the
//!    owner access token (ES256 JWT, 24 hours, `sub` the Telematik-ID), or `401` with
//!    the directory's `{message, errors}`.
//!
//! The core is sans I/O: [`owner`]'s steps build [`http::Request`]s and consume
//! [`http::Response`]s, and [`owner::login`] runs them over a [`http::Transport`]. The
//! decoupled variants for the gematik Authenticator app are not implemented.

#![forbid(unsafe_code)]

mod error;
pub mod owner;

pub use error::{AttributeError, DirectoryError, Error};
pub use ti_idpd::http;
pub use ti_idpd::{Env, Idp};

/// A FHIR-Directory and the IDP-Dienst it authenticates owners with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Directory {
    base_url: String,
    idp: Idp,
}

impl Directory {
    /// The directory at `base_url` (scheme and host, no trailing slash needed), which
    /// must redirect to `idp` and no other.
    pub fn new(base_url: &str, idp: Idp) -> Directory {
        Directory {
            base_url: base_url.trim_end_matches('/').to_owned(),
            idp,
        }
    }

    /// gematik's FHIR-Directory of `env` with the environment's IDP-Dienst:
    /// production, test (TU) or reference (also for development).
    pub fn for_env(env: Env) -> Directory {
        Directory::new(
            match env {
                Env::Prod => "https://fhir-directory.vzd.ti-dienste.de",
                Env::Test => "https://fhir-directory-tu.vzd.ti-dienste.de",
                _ => "https://fhir-directory-ref.vzd.ti-dienste.de",
            },
            Idp::for_env(env),
        )
    }

    /// The base URL.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// The IDP-Dienst the directory may send the client to.
    pub fn idp(&self) -> &Idp {
        &self.idp
    }
}
