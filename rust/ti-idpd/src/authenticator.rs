//! The whole flow over a [`Transport`]: discovery, keys, challenge, answer, code.

use jwz::keys::Signer;

use crate::challenge::{self, CodeRedirect};
use crate::discovery::{self, Discovery};
use crate::error::Error;
use crate::http::Transport;
use crate::{Idp, Warning};

/// The card identity that answers challenges: its signer and its AUT certificate.
pub struct Identity<'a> {
    /// Signs the nested JWT; its algorithm must be `BP256R1` for the IDP-Dienst.
    pub signer: &'a dyn Signer,
    /// The AUT certificate, DER, for the `x5c` header.
    pub certificate_der: &'a [u8],
}

/// What an authentication yielded.
#[derive(Clone, Debug)]
pub struct Authenticated {
    /// The code redirect for the relying party.
    pub redirect: CodeRedirect,
    /// The discovery document that was used.
    pub discovery: Discovery,
    /// The challenge's claims (`client_id`, `scope`, `state`, …), for the record.
    pub challenge_claims: serde_json::Value,
    /// What was not proven along the way.
    pub warnings: Vec<Warning>,
}

/// Runs the Authenticator-Modul flow for `authorization_url` at `idp` with `identity`,
/// judging token validity at `now` (seconds since the epoch).
///
/// # Errors
///
/// The first failing step's [`Error`].
pub fn authenticate<T: Transport>(
    transport: &T,
    idp: &Idp,
    identity: &Identity<'_>,
    authorization_url: &str,
    now: u64,
) -> Result<Authenticated, Error> {
    let send = |what: &'static str, request| {
        transport
            .send(&request)
            .map_err(|source| Error::Transport { what, source })
    };
    let discovery = discovery::parse(&send("discovery document", discovery::request(idp))?, now)?;
    let metadata = &discovery.metadata;
    let puk_idp_sig = discovery::parse_key(
        "PuK_IDP_SIG",
        &send(
            "PuK_IDP_SIG",
            discovery::key_request(&metadata.uri_puk_idp_sig),
        )?,
    )?;
    let puk_idp_enc = discovery::parse_key(
        "PuK_IDP_ENC",
        &send(
            "PuK_IDP_ENC",
            discovery::key_request(&metadata.uri_puk_idp_enc),
        )?,
    )?;
    let challenge = challenge::parse(
        &send("challenge", challenge::request(authorization_url))?,
        &puk_idp_sig,
        now,
    )?;
    let answer = challenge::respond(
        &challenge,
        identity.signer,
        identity.certificate_der,
        &puk_idp_enc,
        metadata,
    )?;
    let redirect = challenge::code(&send("signed challenge", answer)?)?;
    let warnings = discovery.warnings.clone();
    Ok(Authenticated {
        redirect,
        discovery,
        challenge_claims: challenge.claims,
        warnings,
    })
}
