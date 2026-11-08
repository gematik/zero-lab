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

//! The `connector get|describe|verify|change` operations: the Konnektor's cards, their
//! certificates and PINs, its state and services, and its verdict on a certificate.

use ti_connector_client::model::{
    self, CardDescription, CertificateCheck, Expiration, Identity, Info, PinOutcome, PinStatus,
    Services, Status,
};
use ti_connector_client::types::{Card, CertRef, Crypt};
use ti_connector_client::{IDENTITY_CARDS, PinType, Transport};
use ti_pki::{Certificate, Timestamp};

use super::session::{Prompt, Session, Wait, call, card_call, card_user, find};
use crate::error::Error;
use crate::pki::inspect::key_algorithm;

/// The Konnektor and the configuration it was reached with.
pub fn info<T: Transport>(session: &Session<T>) -> Info {
    Info::new(
        &session.name,
        &session.dotkon,
        session.connector.directory(),
    )
}

/// The services of the Konnektor's service directory.
pub fn services<T: Transport>(session: &Session<T>) -> Services {
    Services::new(session.connector.directory())
}

/// The cards in the Konnektor's terminals.
///
/// # Errors
///
/// [`Error::Connector`].
pub fn cards<T: Transport>(session: &Session<T>) -> Result<Vec<model::Card>, Error> {
    let cards = call(session.connector.cards().list(&[]))?;
    Ok(cards.iter().map(model::Card::from).collect())
}

/// The certificates of the card `card` names, judged now.
///
/// # Errors
///
/// [`Error::Connector`], [`Error::CardRestricted`], or the card's user ID
/// ([`card_user`]).
pub fn certificates<T: Transport>(
    session: &Session<T>,
    card: &str,
) -> Result<model::Certificates, Error> {
    let card = find(session, card)?;
    let user = card_user(session, &card)?;
    let certificates = session.connector.certificates().as_user(user.as_ref());
    let read = card_call(
        &card,
        certificates.read_all(&card.card_handle, card.card_type),
    )?;
    let now = Timestamp::now();
    Ok(model::Certificates {
        card: model::Card::from(&card),
        certificates: read
            .iter()
            .map(|c| model::Certificate::new(c, now, key_algorithm(&c.certificate, now)))
            .collect(),
    })
}

/// The Konnektor's VPN connections and error conditions.
///
/// # Errors
///
/// [`Error::Connector`].
pub fn status<T: Transport>(session: &Session<T>) -> Result<Status, Error> {
    Ok(Status::new(call(session.connector.status())?))
}

/// The Telematik-ID of `card`; `None` for a card without one or whose C.AUT cannot be
/// read, which is still shown, without an ID.
fn telematik_id<T: Transport>(session: &Session<T>, card: &Card) -> Option<String> {
    let user = card_user(session, card).ok()?;
    crate::block_on(
        session
            .connector
            .certificates()
            .as_user(user.as_ref())
            .telematik_id(&card.card_handle),
    )
    .ok()?
}

/// The cards that carry an identity, each with its Telematik-ID.
///
/// # Errors
///
/// [`Error::Connector`].
pub fn identities<T: Transport>(session: &Session<T>) -> Result<Vec<Identity>, Error> {
    let cards = call(session.connector.cards().list(&IDENTITY_CARDS))?;
    Ok(cards
        .iter()
        .map(|card| Identity::new(card, telematik_id(session, card)))
        .collect())
}

/// When the certificates of `crypt` expire: of the card `card` names, or of every card
/// and the Konnektor's own.
///
/// # Errors
///
/// [`Error::Connector`], [`Error::CardRestricted`], or the card's user ID.
pub fn expiration<T: Transport>(
    session: &Session<T>,
    card: Option<&str>,
    crypt: Crypt,
) -> Result<Vec<Expiration>, Error> {
    let card = card.map(|card| find(session, card)).transpose()?;
    let handle = card.as_ref().map(|c| c.card_handle.as_str());
    let user = match &card {
        Some(card) => card_user(session, card)?,
        None => None,
    };
    let certificates = session.connector.certificates().as_user(user.as_ref());
    let future = certificates.expiration(handle, crypt);
    let expiry = match &card {
        Some(card) => card_call(card, future)?,
        None => call(future)?,
    };
    Ok(expiry.into_iter().map(Expiration::from).collect())
}

/// The status of each of `card`'s user PINs. A failed query is reported per PIN, so the
/// rest of the description still shows.
fn pin_statuses<T: Transport>(session: &Session<T>, card: &Card) -> Result<Vec<PinStatus>, Error> {
    let user = card_user(session, card)?;
    let pins = session.connector.pins().as_user(user.as_ref());
    Ok(PinType::for_card(card.card_type)
        .iter()
        .map(|pin| {
            let status = call(pins.status(&card.card_handle, *pin)).map_err(|e| e.to_string());
            PinStatus::new(*pin, status)
        })
        .collect())
}

/// The card `card` names, with its Telematik-ID and the state of its user PINs.
///
/// # Errors
///
/// [`Error::Connector`], or the card's user ID.
pub fn describe<T: Transport>(session: &Session<T>, card: &str) -> Result<CardDescription, Error> {
    let found = find(session, card)?;
    let holder = IDENTITY_CARDS.contains(&found.card_type);
    Ok(CardDescription {
        card: model::Card::from(&found),
        telematik_id: holder.then(|| telematik_id(session, &found)).flatten(),
        pins: pin_statuses(session, &found)?,
    })
}

/// Certificate `cert_ref` of `crypt` from the card `card` names, with where it came from,
/// e.g. `C.AUT ECC of SMC-B 80276001011699910102`.
///
/// # Errors
///
/// [`Error::NoCertificate`] for a card without it, [`Error::Connector`],
/// [`Error::CardRestricted`], or the card's user ID.
pub fn card_certificate<T: Transport>(
    session: &Session<T>,
    card: &str,
    cert_ref: CertRef,
    crypt: Crypt,
) -> Result<(String, Certificate), Error> {
    let card = find(session, card)?;
    let user = card_user(session, &card)?;
    let certificates = session.connector.certificates().as_user(user.as_ref());
    let read = card_call(
        &card,
        certificates.read(&card.card_handle, crypt, &[cert_ref]),
    )?;
    let what = format!("{cert_ref} {crypt} of {}", model::Card::from(&card).label());
    match read.into_iter().next() {
        Some(c) => Ok((what, c.certificate)),
        None => Err(Error::NoCertificate { source_name: what }),
    }
}

/// Verifies `pin` (or changes it, if `change`) on the card `card` names, at the card
/// terminal: `wait` is told before the call blocks, and what it returns is dropped when
/// the call returns. No PIN passes through here; the user enters it at the terminal.
///
/// # Errors
///
/// [`Error::PinType`] for a PIN the card does not have, [`Error::Connector`],
/// [`Error::CardRestricted`], or the card's user ID.
pub fn pin<T: Transport, G>(
    session: &Session<T>,
    card: &str,
    pin: Option<PinType>,
    change: bool,
    wait: impl FnOnce(&Wait<'_>) -> G,
) -> Result<PinOutcome, Error> {
    let card = find(session, card)?;
    let pin_type = PinType::choose(card.card_type, pin).map_err(Error::PinType)?;
    let shown = model::Card::from(&card);
    let waiting = wait(&Wait {
        prompt: if change {
            Prompt::ChangePin(pin_type)
        } else {
            Prompt::EnterPin(pin_type)
        },
        card: &shown,
        job_number: None,
    });
    let user = card_user(session, &card);
    let response = user.and_then(|user| {
        let pins = session.connector.pins().as_user(user.as_ref());
        if change {
            card_call(&card, pins.change(&card.card_handle, pin_type))
        } else {
            card_call(&card, pins.verify(&card.card_handle, pin_type))
        }
    });
    drop(waiting);
    let response = response?;
    Ok(PinOutcome {
        card: shown,
        pin: pin_type.as_str(),
        result: response.pin_result.as_str(),
        left_tries: response.left_tries,
    })
}

/// The Konnektor's verdict on `certificate`, at `at` or its current time: path
/// validation against the TI's trust space and OCSP.
///
/// # Errors
///
/// [`Error::Connector`].
pub fn verify_certificate<T: Transport>(
    session: &Session<T>,
    certificate: &Certificate,
    at: Option<Timestamp>,
) -> Result<CertificateCheck, Error> {
    let verdict = call(
        session
            .connector
            .certificates()
            .verify(certificate.der(), at),
    )?;
    Ok(CertificateCheck::new(certificate, verdict))
}
