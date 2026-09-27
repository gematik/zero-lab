//! CertificateService: the certificates on a card, their expiry, and the Konnektor's
//! own certificate check.

use core::fmt;

use ti_pki::Certificate;
use ti_pki::admission::AdmissionStatement;
use ti_types::Timestamp;

use crate::api::gematik::conn::certificateservice602::{
    CheckCertificateExpiration, CheckCertificateExpirationInput, ReadCardCertificate,
    ReadCardCertificateCertRefList, ReadCardCertificateInput, VerifyCertificate,
    VerifyCertificateInput,
};
use crate::connector::Connector;
use crate::error::Error;
use crate::soap::Transport;
use crate::types::{CardType, CertRef, CertificateExpiration, CertificateVerification, Crypt};

/// A certificate read from a card.
#[derive(Clone)]
pub struct CardCertificate {
    /// Which of the card's keys it certifies.
    pub cert_ref: CertRef,
    /// Its key type.
    pub crypt: Crypt,
    /// The certificate.
    pub certificate: Certificate,
    /// Its admission (profession, registration number), if it has one.
    pub admission: Option<AdmissionStatement>,
}

impl CardCertificate {
    /// The Telematik-ID: the admission's registration number.
    pub fn telematik_id(&self) -> Option<&str> {
        self.admission.as_ref()?.registration_number.as_deref()
    }
}

impl fmt::Debug for CardCertificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CardCertificate")
            .field("cert_ref", &self.cert_ref)
            .field("crypt", &self.crypt)
            .field("subject", &self.certificate.subject_cn())
            .field("telematik_id", &self.telematik_id())
            .finish_non_exhaustive()
    }
}

/// The certificates a card type carries, as the Go client reads them; `None` for card
/// types without certificates of their own (eGK, KVK).
pub fn cert_refs(card_type: CardType) -> Option<&'static [CertRef]> {
    match card_type {
        CardType::Hba => Some(&[CertRef::CAut, CertRef::CQes, CertRef::CEnc]),
        CardType::SmcB | CardType::HsmB | CardType::SmB => {
            Some(&[CertRef::CAut, CertRef::CSig, CertRef::CEnc])
        }
        CardType::SmcKt => Some(&[CertRef::CAut]),
        _ => None,
    }
}

/// The certificates facade; see [`Connector::certificates`].
#[derive(Debug)]
pub struct Certificates<'a, T> {
    connector: &'a Connector<T>,
}

impl<T: Transport> Connector<T> {
    /// Card certificates and certificate checks (CertificateService).
    pub fn certificates(&self) -> Certificates<'_, T> {
        Certificates { connector: self }
    }
}

impl<T: Transport> Certificates<'_, T> {
    /// The certificates `refs` of `crypt` from the card with `handle`; references the
    /// card has no certificate for are left out.
    ///
    /// # Errors
    ///
    /// As [`Error`]; [`Error::Decode`] if a certificate does not parse.
    pub async fn read(
        &self,
        handle: &str,
        crypt: Crypt,
        refs: &[CertRef],
    ) -> Result<Vec<CardCertificate>, Error> {
        let response = self
            .connector
            .call::<ReadCardCertificateInput>(ReadCardCertificate {
                card_handle: handle.to_owned(),
                context: self.connector.context(),
                cert_ref_list: ReadCardCertificateCertRefList {
                    cert_ref: refs.iter().map(|r| r.as_str().to_owned()).collect(),
                },
                crypt: Some(crypt),
            })
            .await?;
        response
            .x509_data_info_list
            .x509_data_info
            .into_iter()
            .filter_map(|info| Some((info.cert_ref, info.x509_data?)))
            .map(|(cert_ref, data)| {
                let certificate = Certificate::from_der(data.x509_certificate.as_ref())
                    .map_err(|e| Error::Decode(format!("{cert_ref} certificate: {e}")))?;
                Ok(CardCertificate {
                    cert_ref,
                    crypt,
                    admission: certificate.admission().ok().flatten(),
                    certificate,
                })
            })
            .collect()
    }

    /// Every certificate of `card`'s type: ECC, then RSA where the card still has RSA
    /// keys.
    ///
    /// # Errors
    ///
    /// As [`read`](Self::read); a fault reading RSA certificates only means the card
    /// has none and is not an error.
    pub async fn read_all(
        &self,
        handle: &str,
        card_type: CardType,
    ) -> Result<Vec<CardCertificate>, Error> {
        let Some(refs) = cert_refs(card_type) else {
            return Ok(Vec::new());
        };
        let mut certificates = self.read(handle, Crypt::Ecc, refs).await?;
        match self.read(handle, Crypt::Rsa, refs).await {
            Ok(rsa) => certificates.extend(rsa),
            Err(Error::Fault(_)) => {}
            Err(e) => return Err(e),
        }
        Ok(certificates)
    }

    /// Expiry dates of the certificates of the card with `handle`, or of all cards and
    /// the Konnektor's own when `handle` is `None`.
    ///
    /// # Errors
    ///
    /// As [`Error`].
    pub async fn expiration(
        &self,
        handle: Option<&str>,
        crypt: Crypt,
    ) -> Result<Vec<CertificateExpiration>, Error> {
        let response = self
            .connector
            .call::<CheckCertificateExpirationInput>(CheckCertificateExpiration {
                card_handle: handle.map(str::to_owned),
                context: self.connector.context(),
                crypt: Some(crypt),
            })
            .await?;
        Ok(response.certificate_expiration)
    }

    /// The Konnektor's verdict on `der`: path validation against the TI trust space and
    /// revocation (OCSP), at `at` or the Konnektor's current time.
    ///
    /// # Errors
    ///
    /// As [`Error`].
    pub async fn verify(
        &self,
        der: &[u8],
        at: Option<Timestamp>,
    ) -> Result<CertificateVerification, Error> {
        self.connector
            .call::<VerifyCertificateInput>(VerifyCertificate {
                context: self.connector.context(),
                x509_certificate: der.to_vec().into(),
                verification_time: at.map(|t| t.to_string()),
            })
            .await
    }
}
