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

//! The whole flow over a [`Transport`]: discovery, keys, challenge, answer, code.

use jwz::keys::AsyncSigner;

use crate::challenge::{self, CodeRedirect};
use crate::discovery::{self, Discovery};
use crate::error::Error;
use crate::http::Transport;
use crate::trust::{CertificateTrust, Checked, IdpCertificate};
use crate::{Idp, Warning};

/// The card identity that answers challenges: its signer and its AUT certificate.
pub struct Identity<'a> {
    /// Signs the nested JWT; its algorithm must be `BP256R1` for the IDP-Dienst. A card
    /// signs through the Konnektor asynchronously; a software key is a `Signer`, and every
    /// `Signer` is an `AsyncSigner`.
    pub signer: &'a dyn AsyncSigner,
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
    /// The IDP's certificates as checked, in the order of the flow.
    pub certificates: Vec<CheckedCertificate>,
    /// What was not proven along the way.
    pub warnings: Vec<Warning>,
}

/// One of the IDP's certificates and what the check made of it.
#[derive(Clone, Debug)]
pub struct CheckedCertificate {
    /// Which.
    pub which: IdpCertificate,
    /// The certificate, DER.
    pub der: Vec<u8>,
    /// Verified, or not checked.
    pub checked: Checked,
}

/// Runs the Authenticator-Modul flow for `authorization_url` at `idp` with `identity`,
/// judging token validity at `now` (seconds since the epoch). The IDP's certificates go
/// to `trust` as soon as they are known, before the card signs anything.
///
/// # Errors
///
/// The first failing step's [`Error`]; [`Error::Untrusted`] when `trust` refuses a
/// certificate.
///
/// Only the signature is awaited; the transport answers synchronously, so a caller
/// with a synchronous signer can run the future with any executor, or poll it once.
pub async fn authenticate<T: Transport>(
    transport: &T,
    idp: &Idp,
    identity: &Identity<'_>,
    authorization_url: &str,
    now: u64,
    trust: &dyn CertificateTrust,
) -> Result<Authenticated, Error> {
    let mut certificates = Vec::new();
    let mut check = |which, der: &[u8], chain: &[Vec<u8>]| {
        let checked = trust
            .check(which, der, chain)
            .map_err(|detail| Error::Untrusted { which, detail })?;
        certificates.push(CheckedCertificate {
            which,
            der: der.to_vec(),
            checked,
        });
        Ok::<_, Error>(())
    };
    let send = |what: &'static str, request| {
        transport
            .send(&request)
            .map_err(|source| Error::Transport { what, source })
    };
    let discovery = discovery::parse(&send("discovery document", discovery::request(idp))?, now)?;
    check(
        IdpCertificate::DiscoverySigner,
        &discovery.signer_der,
        &discovery.signer_chain_der,
    )?;
    let metadata = &discovery.metadata;
    let puk_idp_sig = discovery::parse_key(
        "PuK_IDP_SIG",
        &send(
            "PuK_IDP_SIG",
            discovery::key_request(&metadata.uri_puk_idp_sig),
        )?,
    )?;
    let sig_chain = discovery::key_certificates("PuK_IDP_SIG", &puk_idp_sig)?;
    check(IdpCertificate::TokenSigner, &sig_chain[0], &sig_chain[1..])?;
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
    )
    .await?;
    let redirect = challenge::code(&send("signed challenge", answer)?)?;
    let warnings = if certificates.iter().any(|c| c.checked == Checked::Unchecked) {
        vec![Warning::IdpCertificatesUnverified]
    } else {
        Vec::new()
    };
    Ok(Authenticated {
        redirect,
        discovery,
        challenge_claims: challenge.claims,
        certificates,
        warnings,
    })
}
