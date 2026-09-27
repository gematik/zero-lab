//! SignatureService 7.5: signing documents with a card (CAdES, PAdES), verifying
//! signatures, and comfort signature. Signing waits for the card, and for an HBA's QES
//! for the user's PIN at the card terminal.

use core::fmt;

use base64::Engine as _;

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
}

impl<T: Transport> Connector<T> {
    /// Signing, signature verification and comfort signature (SignatureService 7.5).
    pub fn signatures(&self) -> Signatures<'_, T> {
        Signatures { connector: self }
    }
}

/// A document as the SignatureService takes it: its bytes and media type.
fn document(id: &str, bytes: &[u8], mime_type: &str) -> Document {
    Document {
        id: Some(id.to_owned()),
        ref_uri: None,
        ref_type: None,
        schema_refs: None,
        short_text: None,
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

impl<T: Transport> Signatures<'_, T> {
    /// Signs `documents` (bytes and media type each) with the card with `handle`, in one
    /// job. With an HBA the Konnektor asks for PIN.QES at the card terminal; an SMC-B's
    /// PIN must be verified before.
    ///
    /// # Errors
    ///
    /// As [`Error`]. A document the Konnektor could not sign has a `Warning` status.
    pub async fn sign(
        &self,
        handle: &str,
        format: SignatureFormat,
        crypt: Option<Crypt>,
        documents: &[(&[u8], &str)],
    ) -> Result<Vec<Signed>, Error> {
        let job_number = self.job_number().await?;
        let requests = documents
            .iter()
            .enumerate()
            .map(|(i, (content, mime_type))| {
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
                    document: document(&id, content, mime_type),
                    include_revocation_info: false,
                }
            })
            .collect();
        let response = self
            .connector
            .call::<SignDocumentInput>(SignDocument {
                card_handle: handle.to_owned(),
                crypt: crypt.map(|c| c.as_str().to_owned()),
                context: self.connector.context(),
                tv_mode: TvMode::None,
                job_number: Some(job_number),
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
                context: self.connector.context(),
                tv_mode: Some(TvMode::None),
                optional_inputs: None,
                document: Some(self::document("doc-0", document, mime_type)),
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
                context: self.connector.context(),
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
                context: self.connector.context(),
                job_number: job_number.to_owned(),
            })
            .await?;
        Ok(response.status)
    }

    /// Switches the HBA with `handle` to comfort signature: after one PIN.QES entry,
    /// further signatures need no PIN until the count or time runs out.
    ///
    /// # Errors
    ///
    /// As [`Error`].
    pub async fn activate_comfort(&self, handle: &str) -> Result<SignatureMode, Error> {
        let response = self
            .connector
            .call::<ActivateComfortSignatureInput>(ActivateComfortSignature {
                card_handle: handle.to_owned(),
                context: self.connector.context(),
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
    /// of an active session.
    ///
    /// # Errors
    ///
    /// As [`Error`].
    pub async fn mode(&self, handle: &str) -> Result<GetSignatureModeResponse, Error> {
        self.connector
            .call::<GetSignatureModeInput>(GetSignatureMode {
                card_handle: handle.to_owned(),
                context: self.connector.context(),
            })
            .await
    }
}
