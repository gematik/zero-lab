//! AuthSignatureService: signing a hash with a card's authentication key (C.AUT).

use base64::Engine as _;

use crate::api::gematik::conn::authsignatureservice741::ExternalAuthenticateInput;
use crate::api::gematik::conn::signatureservice74::{
    BinaryDocumentType, ExternalAuthenticate, ExternalAuthenticateOptionalInputs,
};
use crate::api::oasis::dss10core::Base64Data;
use crate::connector::Connector;
use crate::error::Error;
use crate::soap::Transport;

/// The signature scheme of [`Auth::external_authenticate`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SignatureType {
    /// ECDSA with the card's curve (BSI TR-03111); the common case for current cards.
    Ecdsa,
    /// RSA PKCS#1 (RFC 3447), for cards with RSA keys.
    Rsa,
}

impl SignatureType {
    /// The URI the Konnektor expects.
    pub const fn uri(self) -> &'static str {
        match self {
            SignatureType::Ecdsa => "urn:bsi:tr:03111:ecdsa",
            SignatureType::Rsa => "urn:ietf:rfc:3447",
        }
    }
}

/// The authentication facade; see [`Connector::auth`].
#[derive(Debug)]
pub struct Auth<'a, T> {
    connector: &'a Connector<T>,
}

impl<T: Transport> Connector<T> {
    /// Signing with a card's authentication key (AuthSignatureService).
    pub fn auth(&self) -> Auth<'_, T> {
        Auth { connector: self }
    }
}

impl<T: Transport> Auth<'_, T> {
    /// Signs `hash`, which the Konnektor does not hash again, with the C.AUT key of the
    /// card with `handle`. An ECDSA signature comes back raw (R‖S, each the curve's
    /// size), also from Konnektors that answer in DER.
    ///
    /// # Errors
    ///
    /// As [`Error`]; [`Error::Decode`] if the response holds no signature.
    pub async fn external_authenticate(
        &self,
        handle: &str,
        hash: &[u8],
        signature_type: SignatureType,
    ) -> Result<Vec<u8>, Error> {
        let response = self
            .connector
            .call::<ExternalAuthenticateInput>(ExternalAuthenticate {
                card_handle: handle.to_owned(),
                context: self.connector.context(),
                optional_inputs: Some(ExternalAuthenticateOptionalInputs {
                    signature_type: Some(signature_type.uri().to_owned()),
                    signature_schemes: None,
                }),
                binary_string: BinaryDocumentType {
                    id: None,
                    ref_uri: None,
                    ref_type: None,
                    schema_refs: None,
                    base64_data: Base64Data {
                        mime_type: Some("application/octet-stream".into()),
                        char_data: base64::engine::general_purpose::STANDARD.encode(hash),
                    },
                },
            })
            .await?;
        let encoded = response
            .signature_object
            .and_then(|o| o.base64_signature)
            .ok_or_else(|| Error::Decode("ExternalAuthenticate: no Base64Signature".into()))?
            .char_data;
        let compact: String = encoded
            .chars()
            .filter(|c| !c.is_ascii_whitespace())
            .collect();
        let signature = base64::engine::general_purpose::STANDARD
            .decode(compact)
            .map_err(|e| Error::Decode(format!("ExternalAuthenticate: {e}")))?;
        Ok(match signature_type {
            SignatureType::Ecdsa => ecdsa_raw(&signature).unwrap_or(signature),
            SignatureType::Rsa => signature,
        })
    }
}

/// R‖S of a DER `ECDSA-Sig-Value`, each padded to the curve size (32, 48 or 66 bytes);
/// `None` if `der` is not one, which is how a raw signature passes through.
fn ecdsa_raw(der: &[u8]) -> Option<Vec<u8>> {
    let (sequence, rest) = tlv(0x30, der)?;
    if !rest.is_empty() {
        return None;
    }
    let (r, rest) = tlv(0x02, sequence)?;
    let (s, rest) = tlv(0x02, rest)?;
    if !rest.is_empty() {
        return None;
    }
    let (r, s) = (strip_zeros(r), strip_zeros(s));
    let size = match r.len().max(s.len()) {
        0..=32 => 32,
        33..=48 => 48,
        49..=66 => 66,
        _ => return None,
    };
    let mut raw = vec![0; 2 * size];
    raw[size - r.len()..size].copy_from_slice(r);
    raw[2 * size - s.len()..].copy_from_slice(s);
    Some(raw)
}

fn strip_zeros(n: &[u8]) -> &[u8] {
    let zeros = n.iter().take_while(|&&b| b == 0).count();
    &n[zeros..]
}

/// The value of a DER element with `tag` at the start of `input`, and what follows.
fn tlv(tag: u8, input: &[u8]) -> Option<(&[u8], &[u8])> {
    let (&first, rest) = input.split_first()?;
    if first != tag {
        return None;
    }
    let (&len, rest) = rest.split_first()?;
    let (len, rest) = match len {
        0..=0x7f => (usize::from(len), rest),
        0x81 => {
            let (&len, rest) = rest.split_first()?;
            (usize::from(len), rest)
        }
        _ => return None,
    };
    (rest.len() >= len).then(|| rest.split_at(len))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn der_signatures_become_fixed_width_raw() {
        // r with a sign byte, s one byte short of 32.
        let mut r = vec![0x00, 0x80];
        r.extend([0x11; 31]);
        let s = vec![0x22; 31];
        let mut der = vec![0x30, 2 + 33 + 2 + 31, 0x02, 33];
        der.extend(&r);
        der.extend([0x02, 31]);
        der.extend(&s);

        let raw = ecdsa_raw(&der).unwrap();
        assert_eq!(raw.len(), 64);
        assert_eq!(&raw[..32], &r[1..]);
        assert_eq!(raw[32], 0);
        assert_eq!(&raw[33..], &s[..]);
    }

    #[test]
    fn raw_signatures_pass_through() {
        assert_eq!(ecdsa_raw(&[0x42; 64]), None);
        assert_eq!(ecdsa_raw(&[0x30, 0x02, 0x02, 0x00]), None);
    }
}
