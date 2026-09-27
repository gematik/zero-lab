//! EncryptionService 6.1: documents encrypted for recipients' certificates (CMS), and
//! decrypted with a card's C.ENC key.

use base64::Engine as _;

use crate::api::gematik::conn::connectorcommon50::Document;
use crate::api::gematik::conn::encryptionservice611::{
    DecryptDocument, DecryptDocumentInput, EncryptDocument, EncryptDocumentInput,
    EncryptDocumentOptionalInputs, EncryptDocumentRecipientKeys, EncryptionType, KeyOnCardType,
};
use crate::api::oasis::dss10core::Base64Data;
use crate::connector::Connector;
use crate::error::Error;
use crate::signatures::decode;
use crate::soap::Transport;
use crate::types::Crypt;

/// The encryption facade; see [`Connector::encryption`].
#[derive(Debug)]
pub struct Encryption<'a, T> {
    connector: &'a Connector<T>,
}

impl<T: Transport> Connector<T> {
    /// Hybrid encryption and decryption of documents (EncryptionService 6.1).
    pub fn encryption(&self) -> Encryption<'_, T> {
        Encryption { connector: self }
    }
}

fn document(bytes: &[u8], mime_type: &str) -> Document {
    Document {
        id: None,
        ref_uri: None,
        ref_type: None,
        schema_refs: None,
        base64_xml: None,
        base64_data: Some(Base64Data {
            mime_type: Some(mime_type.to_owned()),
            char_data: base64::engine::general_purpose::STANDARD.encode(bytes),
        }),
    }
}

fn content(document: Option<Document>) -> Result<Vec<u8>, Error> {
    match document.and_then(|d| d.base64_data) {
        Some(data) => decode(&data.char_data),
        None => Err(Error::Decode("response without a document".into())),
    }
}

impl<T: Transport> Encryption<'_, T> {
    /// `document` encrypted as CMS (RFC 5652) for the holders of `recipients`, DER
    /// certificates with encryption keys (C.ENC, C.HCI.ENC).
    ///
    /// # Errors
    ///
    /// As [`Error`].
    pub async fn encrypt(
        &self,
        recipients: &[&[u8]],
        document: &[u8],
        mime_type: &str,
    ) -> Result<Vec<u8>, Error> {
        let response = self
            .connector
            .call::<EncryptDocumentInput>(EncryptDocument {
                context: self.connector.context(),
                recipient_keys: EncryptDocumentRecipientKeys {
                    certificate_on_card: None,
                    certificate: recipients.iter().map(|r| r.to_vec().into()).collect(),
                },
                document: self::document(document, mime_type),
                optional_inputs: Some(EncryptDocumentOptionalInputs {
                    encryption_type: Some(EncryptionType::UrnIetfRfc5652),
                    element: Vec::new(),
                    unprotected_properties: None,
                }),
            })
            .await?;
        content(response.document)
    }

    /// `document` (CMS) decrypted with the C.ENC key of the card with `handle`.
    /// `mime_type` is the plaintext's media type, as given to [`encrypt`](Self::encrypt):
    /// the Konnektor checks the decrypted content against it (4024 when it does not
    /// match), and labels encrypted documents with it too.
    ///
    /// # Errors
    ///
    /// As [`Error`].
    pub async fn decrypt(
        &self,
        handle: &str,
        crypt: Option<Crypt>,
        document: &[u8],
        mime_type: &str,
    ) -> Result<Vec<u8>, Error> {
        let response = self
            .connector
            .call::<DecryptDocumentInput>(DecryptDocument {
                context: self.connector.context(),
                private_key_on_card: KeyOnCardType {
                    card_handle: handle.to_owned(),
                    key_reference: None,
                    crypt: crypt.map(|c| c.as_str().to_owned()),
                },
                document: self::document(document, mime_type),
                optional_inputs: None,
            })
            .await?;
        content(response.document)
    }
}
