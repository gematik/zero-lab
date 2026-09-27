//! SignatureService 7.5: signing documents with a card (CAdES, PAdES), verifying
//! signatures, and comfort signature. Signing waits for the card, and for an HBA's QES
//! for the user's PIN at the card terminal.

use core::fmt::{self, Write as _};

use base64::Engine as _;

use crate::api::gematik::conn::connectorcontext20::Context;
use crate::api::gematik::conn::signatureservice75::{
    ActivateComfortSignature, ActivateComfortSignatureInput, DeactivateComfortSignature,
    DeactivateComfortSignatureInput, Document, GetJobNumber, GetJobNumberInput, GetSignatureMode,
    GetSignatureModeInput, GetSignatureModeResponse, SignDocument, SignDocumentInput, SignRequest,
    SignRequestOptionalInputs, StopSignature, StopSignatureInput, TvMode, VerifyDocument,
    VerifyDocumentInput, VerifyDocumentResponse,
};
use crate::api::oasis::dss10core::{Base64Data, Base64Signature, SignatureObject};
use crate::connector::Connector;
use crate::error::Error;
use crate::soap::Transport;
use crate::types::{Crypt, SignatureMode, Status};

/// The signature format.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SignatureFormat {
    /// CMS (RFC 5652), detached: the signature without the document.
    Cades,
    /// PDF signature, in the signed PDF. Konnektors sign PDF/A (`application/pdf-a`).
    Pades,
}

impl SignatureFormat {
    /// The `SignatureType` URI.
    pub const fn uri(self) -> &'static str {
        match self {
            SignatureFormat::Cades => "urn:ietf:rfc:5652",
            SignatureFormat::Pades => "http://uri.etsi.org/02778/3",
        }
    }

    /// `cades` or `pades`.
    pub const fn as_str(self) -> &'static str {
        match self {
            SignatureFormat::Cades => "cades",
            SignatureFormat::Pades => "pades",
        }
    }
}

impl fmt::Display for SignatureFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One document's signature.
#[derive(Clone, Debug)]
pub struct Signed {
    /// The Konnektor's status for this document; `Warning` carries its reason.
    pub status: Status,
    /// CAdES: the CMS signature.
    pub signature: Option<Vec<u8>>,
    /// PAdES: the PDF with its signature.
    pub signed_document: Option<Vec<u8>>,
}

/// The signature facade; see [`Connector::signatures`].
#[derive(Debug)]
pub struct Signatures<'a, T> {
    connector: &'a Connector<T>,
    /// The comfort signature session's user, replacing the `.kon` file's.
    user: Option<&'a ComfortUserId>,
}

/// The UserId of a comfort signature session: a random UUID (RFC 4122, version 4).
/// The Konnektor refuses a UserId that is not a 128-bit UUID (A_20073-01, error 4272) or
/// that one of its last 1,000 operations used (A_20074, error 4270); gematik's client
/// guidance (A_21528) takes a new one for each activation. Every call of the session
/// (activation, signature mode, signing) carries the same one.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ComfortUserId(String);

impl ComfortUserId {
    /// A new UserId from 16 bytes of `fill_random`, which must be a cryptographically
    /// secure source.
    pub fn generate(fill_random: impl FnOnce(&mut [u8; 16])) -> Self {
        let mut b = [0u8; 16];
        fill_random(&mut b);
        b[6] = (b[6] & 0x0f) | 0x40;
        b[8] = (b[8] & 0x3f) | 0x80;
        let hex = b.iter().fold(String::with_capacity(32), |mut hex, x| {
            write!(hex, "{x:02x}").expect("writing to a String cannot fail");
            hex
        });
        ComfortUserId(format!(
            "{}-{}-{}-{}-{}",
            &hex[..8],
            &hex[8..12],
            &hex[12..16],
            &hex[16..20],
            &hex[20..]
        ))
    }

    /// A stored UserId, if it is a UUID (`8-4-4-4-12` hex digits).
    pub fn parse(text: &str) -> Option<Self> {
        let groups: Vec<&str> = text.split('-').collect();
        let shape = groups.iter().map(|g| g.len()).eq([8, 4, 4, 4, 12]);
        let hex = groups
            .iter()
            .all(|g| g.bytes().all(|b| b.is_ascii_hexdigit()));
        (shape && hex).then(|| ComfortUserId(text.to_ascii_lowercase()))
    }

    /// The UUID text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ComfortUserId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl<T: Transport> Connector<T> {
    /// Signing, signature verification and comfort signature (SignatureService 7.5).
    pub fn signatures(&self) -> Signatures<'_, T> {
        Signatures {
            connector: self,
            user: None,
        }
    }
}

/// A document to sign.
#[derive(Clone, Copy, Debug)]
pub struct ToSign<'a> {
    /// The bytes.
    pub content: &'a [u8],
    /// Their media type; `application/pdf-a` for PAdES.
    pub mime_type: &'a str,
    /// What the card terminal shows while the user enters PIN.QES (the Konnektor's
    /// schema allows 30 characters); required for a qualified signature with an HBA.
    pub short_text: Option<&'a str>,
}

/// A document as the SignatureService takes it.
fn document(id: &str, bytes: &[u8], mime_type: &str, short_text: Option<&str>) -> Document {
    Document {
        id: Some(id.to_owned()),
        ref_uri: None,
        ref_type: None,
        schema_refs: None,
        short_text: short_text.map(str::to_owned),
        base64_xml: None,
        base64_data: Some(Base64Data {
            mime_type: Some(mime_type.to_owned()),
            char_data: base64::engine::general_purpose::STANDARD.encode(bytes),
        }),
    }
}

/// The bytes of a document the Konnektor returned.
fn bytes(document: Document) -> Result<Vec<u8>, Error> {
    match (document.base64_xml, document.base64_data) {
        (Some(xml), _) => Ok(xml.into()),
        (None, Some(data)) => decode(&data.char_data),
        (None, None) => Err(Error::Decode("document without content".into())),
    }
}

pub(crate) fn decode(text: &str) -> Result<Vec<u8>, Error> {
    let compact: String = text.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    base64::engine::general_purpose::STANDARD
        .decode(compact)
        .map_err(|e| Error::Decode(format!("base64: {e}")))
}

impl<'a, T: Transport> Signatures<'a, T> {
    /// Signs within the comfort signature session of `user`: no PIN entry per signature
    /// while the session lasts.
    #[must_use]
    pub fn as_user(self, user: &'a ComfortUserId) -> Self {
        Signatures {
            user: Some(user),
            ..self
        }
    }

    fn context(&self, user: Option<&ComfortUserId>) -> Context {
        let mut context = self.connector.context();
        if let Some(user) = user {
            context.user_id = Some(user.as_str().to_owned());
        }
        context
    }

    /// Signs `documents` with the card with `handle`, in one job. With an HBA the
    /// signature is qualified: the Konnektor asks for PIN.QES at the card terminal and
    /// requires each document's short text. An SMC-B's PIN must be verified before.
    ///
    /// # Errors
    ///
    /// As [`Error`]. A document the Konnektor could not sign has a `Warning` status.
    pub async fn sign(
        &self,
        handle: &str,
        format: SignatureFormat,
        crypt: Option<Crypt>,
        documents: &[ToSign<'_>],
    ) -> Result<Vec<Signed>, Error> {
        let job_number = self.job_number().await?;
        self.sign_in_job(&job_number, handle, format, crypt, documents)
            .await
    }

    /// [`sign`](Self::sign) within the job `job_number` from
    /// [`job_number`](Self::job_number). The card terminal shows it at PIN.QES entry, so
    /// a client that shows it too lets the user match prompt and job.
    ///
    /// # Errors
    ///
    /// As [`sign`](Self::sign).
    pub async fn sign_in_job(
        &self,
        job_number: &str,
        handle: &str,
        format: SignatureFormat,
        crypt: Option<Crypt>,
        documents: &[ToSign<'_>],
    ) -> Result<Vec<Signed>, Error> {
        let requests = documents
            .iter()
            .enumerate()
            .map(|(i, d)| {
                let id = format!("doc-{i}");
                SignRequest {
                    request_id: format!("request-{i}"),
                    optional_inputs: Some(SignRequestOptionalInputs {
                        signature_type: Some(format.uri().to_owned()),
                        properties: None,
                        include_enveloped_content: None,
                        include_objects: None,
                        signature_placement: None,
                        return_updated_signature: None,
                        schemas: None,
                        generate_under_signature_policy: None,
                        viewer_info: None,
                    }),
                    document: document(&id, d.content, d.mime_type, d.short_text),
                    include_revocation_info: false,
                }
            })
            .collect();
        let response = self
            .connector
            .call::<SignDocumentInput>(SignDocument {
                card_handle: handle.to_owned(),
                crypt: crypt.map(|c| c.as_str().to_owned()),
                context: self.context(self.user),
                tv_mode: TvMode::None,
                job_number: Some(job_number.to_owned()),
                sign_request: requests,
            })
            .await?;
        response
            .sign_response
            .into_iter()
            .map(|r| {
                let signature = r
                    .signature_object
                    .and_then(|o| o.base64_signature)
                    .map(|s| decode(&s.char_data))
                    .transpose()?;
                let signed_document = r
                    .optional_outputs
                    .and_then(|o| o.document_with_signature)
                    .map(bytes)
                    .transpose()?
                    // A detached signature comes with an empty document.
                    .filter(|d| !d.is_empty());
                // Konnektors return a signed PDF as the signature object (gematik's
                // examples) or as the document with signature.
                let (signature, signed_document) = match (format, signature, signed_document) {
                    (SignatureFormat::Pades, Some(pdf), None) => (None, Some(pdf)),
                    other => (other.1, other.2),
                };
                Ok(Signed {
                    status: r.status,
                    signature,
                    signed_document,
                })
            })
            .collect()
    }

    /// Verifies a signature: CAdES with the signed `document` and its detached
    /// `signature`; PAdES with the signed PDF alone.
    ///
    /// # Errors
    ///
    /// As [`Error`]. An invalid signature is not an error: see the result.
    pub async fn verify(
        &self,
        format: SignatureFormat,
        document: &[u8],
        mime_type: &str,
        signature: Option<&[u8]>,
    ) -> Result<VerifyDocumentResponse, Error> {
        self.connector
            .call::<VerifyDocumentInput>(VerifyDocument {
                context: self.context(self.user),
                tv_mode: Some(TvMode::None),
                optional_inputs: None,
                document: Some(self::document("doc-0", document, mime_type, None)),
                signature_object: signature.map(|s| SignatureObject {
                    schema_refs: None,
                    signature: None,
                    timestamp: None,
                    base64_signature: Some(Base64Signature {
                        r#type: Some(format.uri().to_owned()),
                        char_data: base64::engine::general_purpose::STANDARD.encode(s),
                    }),
                    signature_ptr: None,
                    other: None,
                }),
                include_revocation_info: false,
            })
            .await
    }

    /// A new job number, which ties a signing job to its PIN entry.
    ///
    /// # Errors
    ///
    /// As [`Error`].
    pub async fn job_number(&self) -> Result<String, Error> {
        let response = self
            .connector
            .call::<GetJobNumberInput>(GetJobNumber {
                context: self.context(self.user),
            })
            .await?;
        Ok(response.job_number)
    }

    /// Cancels the signing job `job_number`.
    ///
    /// # Errors
    ///
    /// As [`Error`].
    pub async fn stop(&self, job_number: &str) -> Result<Status, Error> {
        let response = self
            .connector
            .call::<StopSignatureInput>(StopSignature {
                context: self.context(self.user),
                job_number: job_number.to_owned(),
            })
            .await?;
        Ok(response.status)
    }

    /// Switches the HBA with `handle` to comfort signature for `user`, a new
    /// [`ComfortUserId`]: after one PIN.QES entry, further signatures by the same user
    /// need no PIN until the count or time runs out.
    ///
    /// # Errors
    ///
    /// As [`Error`].
    pub async fn activate_comfort(
        &self,
        handle: &str,
        user: &ComfortUserId,
    ) -> Result<SignatureMode, Error> {
        let response = self
            .connector
            .call::<ActivateComfortSignatureInput>(ActivateComfortSignature {
                card_handle: handle.to_owned(),
                context: self.context(Some(user)),
            })
            .await?;
        Ok(response.signature_mode)
    }

    /// Ends comfort signature for the HBAs with `handles`.
    ///
    /// # Errors
    ///
    /// As [`Error`].
    pub async fn deactivate_comfort(&self, handles: &[&str]) -> Result<Status, Error> {
        let response = self
            .connector
            .call::<DeactivateComfortSignatureInput>(DeactivateComfortSignature {
                card_handle: handles.iter().map(|h| (*h).to_owned()).collect(),
            })
            .await?;
        Ok(response.status)
    }

    /// Whether comfort signature is enabled for the HBA with `handle`, and what is left
    /// of the session of `user`.
    ///
    /// # Errors
    ///
    /// As [`Error`].
    pub async fn mode(
        &self,
        handle: &str,
        user: &ComfortUserId,
    ) -> Result<GetSignatureModeResponse, Error> {
        self.connector
            .call::<GetSignatureModeInput>(GetSignatureMode {
                card_handle: handle.to_owned(),
                context: self.context(Some(user)),
            })
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn comfort_user_ids_are_version_4_uuids() {
        let id = ComfortUserId::generate(|b| b.fill(0xff));
        assert_eq!(id.as_str(), "ffffffff-ffff-4fff-bfff-ffffffffffff");
        let id = ComfortUserId::generate(|b| b.fill(0));
        assert_eq!(id.as_str(), "00000000-0000-4000-8000-000000000000");
        assert_eq!(ComfortUserId::parse(id.as_str()), Some(id));
        assert_eq!(
            ComfortUserId::parse("0987654321"),
            None,
            "a .kon user ID is no UUID"
        );
        assert_eq!(
            ComfortUserId::parse("0000000g-0000-4000-8000-000000000000"),
            None
        );
    }
}
