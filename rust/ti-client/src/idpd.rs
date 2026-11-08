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

//! The IDP-Dienst's Authenticator-Modul flow with an identity, from an authorization URL
//! to the authorization code: what an ePA client does for
//! `send_authorization_request_sc` → `send_authcode_sc`.

use core::fmt;

use jwz::keys::AsyncSigner;
use serde::Serialize;
use ti_idpd_client::authenticator::{self, Authenticated};
use ti_idpd_client::model::{ChallengeInfo, IdpInfo};
use ti_idpd_client::{Idp, Warning};
use ti_pki::Timestamp;

use crate::block_on;
use crate::error::Error;
use crate::identity::Identity;
use crate::idp_trust::IdpTrust;

/// An identity ready for the IDP-Dienst, which speaks `BP256R1` only.
pub struct Card<'a> {
    identity: &'a Identity,
    signer: Box<dyn AsyncSigner>,
}

impl<'a> Card<'a> {
    /// `identity` with its signer for the IDP-Dienst.
    ///
    /// # Errors
    ///
    /// [`Error::KeyUnsupported`] for a key that is not on brainpoolP256r1.
    pub fn new(identity: &'a Identity) -> Result<Card<'a>, Error> {
        Ok(Card {
            identity,
            signer: identity.signer(ti_jwz::brainpool::BP256R1)?,
        })
    }

    /// The identity as the flow takes it.
    pub fn authenticator(&self) -> authenticator::Identity<'_> {
        authenticator::Identity {
            signer: &*self.signer,
            certificate_der: self.identity.certificate.der(),
        }
    }

    /// What a report shows of the identity.
    pub fn info(&self) -> IdentityInfo {
        IdentityInfo {
            subject: self.identity.certificate.subject().to_string(),
            telematik_id: self.identity.telematik_id(),
        }
    }
}

/// The identity that authenticated.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct IdentityInfo {
    /// Its certificate's subject.
    pub subject: String,
    /// Its Telematik-ID, if the certificate has one.
    pub telematik_id: Option<String>,
}

/// The flow's result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Authentication {
    /// The authorization code for the relying party.
    pub code: String,
    /// The `state` the relying party sent, if any.
    pub state: Option<String>,
    /// The redirect the IDP answered with, as sent.
    pub redirect_url: String,
    /// The IDP and its certificates.
    pub idp: IdpInfo,
    /// The identity that authenticated.
    pub identity: IdentityInfo,
    /// Claims of the challenge, for the record.
    pub challenge: ChallengeInfo,
    /// What was not proven: `idp_certificates_unverified` without a check of the IDP's
    /// certificates.
    pub warnings: Vec<&'static str>,
}

/// The authorization code `idp` issues for `auth_url` to `card`, the IDP's certificates
/// judged by `trust`.
///
/// # Errors
///
/// The front end's error for trust material that could not be loaded, which a refusal
/// of the IDP's certificates stands for; [`Error::Idpd`] otherwise.
pub fn authenticate<T, E>(
    transport: &T,
    idp: &Idp,
    card: &Card<'_>,
    auth_url: &str,
    trust: &IdpTrust<'_, E>,
) -> Result<Authentication, E>
where
    T: ti_idpd_client::http::Transport,
    E: From<Error> + fmt::Display,
{
    let done = block_on(authenticator::authenticate(
        transport,
        idp,
        &card.authenticator(),
        auth_url,
        Timestamp::now,
        trust,
    ))
    .map_err(|error| idpd_error(trust, error))?;
    Ok(Authentication {
        idp: IdpInfo::new(idp, &done),
        identity: card.info(),
        challenge: ChallengeInfo::from(&done),
        warnings: warnings(&done),
        code: done.redirect.code,
        state: done.redirect.state,
        redirect_url: done.redirect.url,
    })
}

/// A failure of the flow as the caller reports it.
pub(crate) fn idpd_error<E: From<Error> + fmt::Display>(
    trust: &IdpTrust<'_, E>,
    error: ti_idpd_client::Error,
) -> E {
    // A refusal of the IDP's certificates may stand for trust material that could not be
    // loaded; that failure is the one to report.
    trust
        .take_error()
        .unwrap_or_else(|| Error::Idpd(error).into())
}

/// The flow's warnings by their stable names.
pub(crate) fn warnings(done: &Authenticated) -> Vec<&'static str> {
    done.warnings.iter().map(|w| Warning::as_str(*w)).collect()
}
