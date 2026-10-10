//! The gematik IDP-Dienst as a Primärsystem's Authenticator-Modul sees it
//! (gemSpec_IDP_Dienst V2.2.0, gemSpec_IDP_Frontend V1.7.1): the signed discovery
//! document, the IDP's signing and encryption keys, and the challenge–response that turns
//! an authorization URL into an authorization code with a smartcard identity.
//!
//! The core is sans I/O: [`discovery`], [`challenge`] and [`authenticator`] build
//! [`http::Request`]s and consume [`http::Response`]s, so any HTTP client drives them;
//! the `ureq` feature adds a blocking [`http::Transport`] for command-line tools.
//!
//! The flow (`tokenFlowPs` of gematik's reference implementation):
//!
//! 1. `GET {idp}/.well-known/openid-configuration`: a compact JWS signed `BP256R1`, its
//!    signer in `x5c`; the payload is the OpenID metadata with `uri_puk_idp_sig` and
//!    `uri_puk_idp_enc`.
//! 2. `GET` both keys as JWKs.
//! 3. `GET` the authorization URL the relying party made (not following redirects):
//!    `200` with `{challenge, user_consent}`, the challenge a JWS by `PuK_IDP_SIG`; a
//!    `302` already carries the IDP's error.
//! 4. The card signs the nested JWT `{"njwt": challenge}` (`alg BP256R1`, `cty NJWT`,
//!    `x5c` the AUT certificate); `{"njwt": <that>}` is encrypted to `PuK_IDP_ENC`
//!    (`ECDH-ES`, `A256GCM`, `cty NJWT`, `exp` of the challenge) and posted as
//!    `signed_challenge`.
//! 5. `302 Location` with `code` (and `state`), or the IDP's error in the query.
//!
//! What this crate does not do yet: verify the IDP's certificates against the TSL (it
//! reports [`Warning::IdpCertificatesUnverified`]; backlog TASK-27), the relying-party
//! side (`key_verifier`, token decryption), SSO tokens, pairing.

#![forbid(unsafe_code)]

pub mod authenticator;
pub mod challenge;
pub mod discovery;
mod error;
pub mod http;
mod query;
#[cfg(feature = "ureq")]
pub mod ureq;

pub use error::{Error, IdpError};
pub use ti_types::Env;

/// An IDP-Dienst: where it lives.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Idp {
    base_url: String,
}

impl Idp {
    /// The IDP at `base_url` (scheme and host, no trailing slash needed).
    pub fn new(base_url: &str) -> Idp {
        Idp {
            base_url: base_url.trim_end_matches('/').to_owned(),
        }
    }

    /// gematik's IDP-Dienst of `env`: production, reference (also for development) or
    /// test.
    pub fn for_env(env: Env) -> Idp {
        Idp::new(match env {
            Env::Prod => "https://idp.app.ti-dienste.de",
            Env::Test => "https://idp-test.app.ti-dienste.de",
            // Dev shares the reference environment, as it does for the trust material;
            // an environment added later gets the reference IDP until named here.
            _ => "https://idp-ref.app.ti-dienste.de",
        })
    }

    /// The base URL.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }
}

/// What a result is right about but could not prove.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Warning {
    /// The discovery document's signer and the key certificates were used without a
    /// check against the TSL and OCSP (gemSpec_IDP_Dienst requires one): the
    /// signatures verified, the signer's standing did not.
    IdpCertificatesUnverified,
}

impl Warning {
    /// The stable snake_case name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Warning::IdpCertificatesUnverified => "idp_certificates_unverified",
        }
    }
}
