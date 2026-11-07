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

//! The `connector sign|encrypt|decrypt|comfort|export` operations and `verify signature`:
//! documents through the Konnektor's SignatureService and EncryptionService, an HBA's
//! comfort signature, and certificates read for export. Documents come in and go out as
//! bytes; reading and writing files is the front end's.

use serde::Serialize;
use ti_connector_client::model::{self, Comfort, SignatureCheck};
use ti_connector_client::types::{Card, CardType, CertRef, Crypt, SignatureMode};
use ti_connector_client::{
    CardCertificate, ComfortUserId, Error as ConnectorError, SignatureFormat, Signatures, ToSign,
    Transport, cert_refs,
};
use ti_pki::Certificate;

use super::session::{
    Prompt, Session, UserIdStore, Wait, call, card_call, card_user, find, new_user_id,
};
use crate::error::Error;

/// A document to sign.
#[derive(Clone, Copy, Debug)]
pub struct ToSignWith<'a> {
    /// The card that signs, as the user names it.
    pub card: &'a str,
    /// The document.
    pub document: &'a [u8],
    /// The signature format.
    pub format: SignatureFormat,
    /// The document's media type.
    pub mime_type: &'a str,
    /// What the card terminal shows at PIN entry.
    pub short_text: &'a str,
    /// The key type to sign with.
    pub crypt: Crypt,
}

/// A signature made.
#[derive(Debug, Serialize)]
pub struct Signed {
    /// `cades` or `pades`.
    pub format: &'static str,
    /// The card that signed.
    pub card: model::Card,
    /// Signed within a comfort signature session, without a PIN entry.
    pub comfort: bool,
    /// The CAdES signature or the signed PDF.
    #[serde(skip)]
    pub bytes: Vec<u8>,
    /// The Konnektor's warning, `code text` of each trace entry: it signed, but says
    /// something about it.
    #[serde(skip)]
    pub warning: Option<String>,
}

/// Signs `request`'s document with its card in a job of its own: `wait` is told before
/// the call blocks at the card terminal, with the job number the terminal shows at PIN
/// entry, and what it returns is dropped when the call returns.
///
/// # Errors
///
/// [`Error::Connector`] (an answer without a signature is a decode error),
/// [`Error::CardRestricted`], or the card's user ID.
pub fn sign<T: Transport, G>(
    session: &Session<T>,
    request: &ToSignWith<'_>,
    wait: impl FnOnce(&Wait<'_>) -> G,
) -> Result<Signed, Error> {
    let card = find(session, request.card)?;
    let user = card_user(session, &card)?;
    let signatures = session.connector.signatures();
    let comfort = in_comfort_session(&card, &signatures, user.as_ref());
    // An HBA's signature is qualified: without a comfort session the user enters PIN.QES.
    let prompt = match (card.card_type, comfort) {
        (CardType::Hba, false) => Prompt::SignWithPin,
        _ => Prompt::Sign,
    };
    let job_number = call(signatures.job_number())?;
    let shown = model::Card::from(&card);
    let waiting = wait(&Wait {
        prompt,
        card: &shown,
        job_number: Some(&job_number),
    });
    let signatures = signatures.as_user(user.as_ref());
    let signed = card_call(
        &card,
        signatures.sign_in_job(
            &job_number,
            &card.card_handle,
            request.format,
            Some(request.crypt),
            &[ToSign {
                content: request.document,
                mime_type: request.mime_type,
                short_text: Some(request.short_text),
            }],
        ),
    );
    drop(waiting);
    let signed = signed?.into_iter().next().ok_or_else(|| {
        Error::Connector(ConnectorError::Decode("SignDocument: no result".into()))
    })?;
    let warning = signed.status.error.as_ref().map(|error| {
        let texts: Vec<String> = error
            .trace
            .iter()
            .map(|t| format!("{} {}", t.code, t.error_text))
            .collect();
        texts.join("; ")
    });
    let bytes = if request.format == SignatureFormat::Pades {
        signed.signed_document
    } else {
        signed.signature
    };
    let bytes = bytes.ok_or_else(|| {
        Error::Connector(ConnectorError::Decode(
            "SignDocument: no signature in the response".into(),
        ))
    })?;
    Ok(Signed {
        format: request.format.as_str(),
        card: shown,
        comfort,
        bytes,
        warning,
    })
}

/// Whether `user` holds a comfort session on `card`. What this cannot find out does not stop
/// the signature: a call the Konnektor refuses for the card fails the same way in the
/// signing itself, with the error to show.
fn in_comfort_session<T: Transport>(
    card: &Card,
    signatures: &Signatures<'_, T>,
    user: Option<&ComfortUserId>,
) -> bool {
    user.and_then(|user| call(signatures.mode(&card.card_handle, user)).ok())
        .and_then(|mode| mode.session_info)
        .is_some_and(|session| session.signature_mode == SignatureMode::Comfort)
}

/// The Konnektor's verdict on `document` signed in `format`, with its `detached`
/// signature for CAdES.
///
/// # Errors
///
/// [`Error::Connector`].
pub fn verify_signature<T: Transport>(
    session: &Session<T>,
    format: SignatureFormat,
    document: &[u8],
    mime_type: &str,
    detached: Option<&[u8]>,
) -> Result<SignatureCheck, Error> {
    let verdict = call(
        session
            .connector
            .signatures()
            .verify(format, document, mime_type, detached),
    )?;
    Ok(SignatureCheck::new(format, verdict.verification_result))
}

/// The ECC encryption certificate (C.ENC) of the card `card` names, a recipient's.
///
/// # Errors
///
/// [`Error::NoCertificate`] for a card without one, [`Error::Connector`],
/// [`Error::CardRestricted`], or the card's user ID.
pub fn encryption_certificate<T: Transport>(
    session: &Session<T>,
    card: &str,
) -> Result<Certificate, Error> {
    let card = find(session, card)?;
    let user = card_user(session, &card)?;
    let certificates = session.connector.certificates().as_user(user.as_ref());
    let read = card_call(
        &card,
        certificates.read(&card.card_handle, Crypt::Ecc, &[CertRef::CEnc]),
    )?;
    let enc = read
        .into_iter()
        .next()
        .ok_or_else(|| Error::NoCertificate {
            source_name: format!("C.ENC ECC of {}", model::Card::from(&card).label()),
        })?;
    Ok(enc.certificate)
}

/// `document` of `mime_type` encrypted for `recipients`, as CMS.
///
/// # Errors
///
/// [`Error::Connector`].
pub fn encrypt<T: Transport>(
    session: &Session<T>,
    recipients: &[Certificate],
    document: &[u8],
    mime_type: &str,
) -> Result<Vec<u8>, Error> {
    let ders: Vec<&[u8]> = recipients.iter().map(Certificate::der).collect();
    call(
        session
            .connector
            .encryption()
            .encrypt(&ders, document, mime_type),
    )
}

/// A document decrypted.
#[derive(Debug)]
pub struct Decrypted {
    /// The card that decrypted.
    pub card: model::Card,
    /// The plain text.
    pub bytes: Vec<u8>,
}

/// `cms` decrypted with the `crypt` key of the card `card` names: `wait` is told before
/// the call blocks at the card terminal, and what it returns is dropped when the call
/// returns.
///
/// # Errors
///
/// [`Error::Connector`], [`Error::CardRestricted`], or the card's user ID.
pub fn decrypt<T: Transport, G>(
    session: &Session<T>,
    card: &str,
    crypt: Crypt,
    cms: &[u8],
    mime_type: &str,
    wait: impl FnOnce(&Wait<'_>) -> G,
) -> Result<Decrypted, Error> {
    let card = find(session, card)?;
    let user = card_user(session, &card)?;
    let shown = model::Card::from(&card);
    let waiting = wait(&Wait {
        prompt: Prompt::Decrypt,
        card: &shown,
        job_number: None,
    });
    let plain = card_call(
        &card,
        session
            .connector
            .encryption()
            .as_user(user.as_ref())
            .decrypt(&card.card_handle, Some(crypt), cms, mime_type),
    );
    drop(waiting);
    Ok(Decrypted {
        card: shown,
        bytes: plain?,
    })
}

/// What to do with an HBA's comfort signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ComfortAction {
    /// Start a session with a new user ID, kept for the card's later calls.
    Activate,
    /// The mode of the card's user ID.
    Status,
    /// End the card's session and forget its user ID.
    Deactivate,
}

/// Runs `action` on the comfort signature of the card `card` names: `wait` is told
/// before activating blocks at the card terminal, and what it returns is dropped when
/// the call returns.
///
/// # Errors
///
/// [`Error::State`] when the user ID cannot be kept or removed, [`Error::Connector`],
/// [`Error::CardRestricted`], [`Error::Randomness`], or the card's user ID.
pub fn comfort<T: Transport, G>(
    session: &Session<T>,
    card: &str,
    action: ComfortAction,
    wait: impl FnOnce(&Wait<'_>) -> G,
) -> Result<Comfort, Error> {
    let card = find(session, card)?;
    let store = UserIdStore::of(session);
    let signatures = session.connector.signatures();
    let shown = model::Card::from(&card);
    let mode = |user: &ComfortUserId| card_call(&card, signatures.mode(&card.card_handle, user));
    match action {
        ComfortAction::Activate => {
            store.prepare()?;
            // A new random user ID for each activation (A_21528), unique among the
            // Konnektor's last 1,000 operations (A_20074).
            let user = new_user_id()?;
            let waiting = wait(&Wait {
                prompt: Prompt::ActivateComfort,
                card: &shown,
                job_number: None,
            });
            let activated = card_call(&card, signatures.activate_comfort(&card.card_handle, &user));
            drop(waiting);
            activated?;
            store.save(&card, &user)?;
            Ok(Comfort::with_mode(shown, mode(&user)?))
        }
        ComfortAction::Status => {
            // With no ID of its own the mode is asked with a fresh one: whether comfort
            // signature is enabled does not depend on it.
            let user = match card_user(session, &card)? {
                Some(user) => user,
                None => new_user_id()?,
            };
            Ok(Comfort::with_mode(shown, mode(&user)?))
        }
        ComfortAction::Deactivate => {
            // A refusal must leave the card session and the file alike.
            store.check()?;
            card_call(&card, signatures.deactivate_comfort(&[&card.card_handle]))?;
            store.remove(&card)?;
            Ok(Comfort::new(shown))
        }
    }
}

/// Certificates read from a card for export.
#[derive(Debug)]
pub struct Export {
    /// The card.
    pub card: model::Card,
    /// The certificates, at least one.
    pub certificates: Vec<CardCertificate>,
}

/// The certificates of the card `card` names: `cert_ref` of `crypt` (ECC unless given),
/// every reference of the card type of `crypt`, or every certificate of the card.
///
/// # Errors
///
/// [`Error::NoCertificate`] when the card has none of them, [`Error::Connector`],
/// [`Error::CardRestricted`], or the card's user ID.
pub fn export<T: Transport>(
    session: &Session<T>,
    card: &str,
    cert_ref: Option<CertRef>,
    crypt: Option<Crypt>,
) -> Result<Export, Error> {
    let card = find(session, card)?;
    let user = card_user(session, &card)?;
    let certificates = session.connector.certificates().as_user(user.as_ref());
    let handle = &card.card_handle;
    let read = match (cert_ref, crypt) {
        (Some(cert_ref), crypt) => card_call(
            &card,
            certificates.read(handle, crypt.unwrap_or(Crypt::Ecc), &[cert_ref]),
        )?,
        (None, Some(crypt)) => {
            let refs = cert_refs(card.card_type).unwrap_or_default();
            card_call(&card, certificates.read(handle, crypt, refs))?
        }
        (None, None) => card_call(&card, certificates.read_all(handle, card.card_type))?,
    };
    let shown = model::Card::from(&card);
    if read.is_empty() {
        return Err(Error::NoCertificate {
            source_name: format!("the requested certificates of {}", shown.label()),
        });
    }
    Ok(Export {
        card: shown,
        certificates: read,
    })
}
