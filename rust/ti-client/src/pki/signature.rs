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

//! An ECDSA-SHA256 signature over some data, checked against a certificate's key with
//! ti-pki's verifiers. An ePA client checks the VAU's `signed_pub_keys` this way; the
//! certificate's own standing is [`super::verify`]'s job.

use serde::Serialize;
use ti_pki::key::classify_key;
use ti_pki::{Certificate, Timestamp, algorithms};

use crate::error::Error;

/// DER contents of the `ecdsa-with-SHA256` AlgorithmIdentifier (RFC 5758 §3.2: no
/// parameters), the form [`algorithms::find`] takes.
const ECDSA_WITH_SHA256: [u8; 10] = [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];

/// The coordinate size of the curves identities sign with.
const COORDINATE: usize = 32;

/// An ECDSA-SHA256 signature checked against a certificate's key.
#[derive(Serialize)]
pub struct SignatureCheck {
    /// Whether the signature verifies.
    pub valid: bool,
    /// Always `SHA-256`.
    pub hash: &'static str,
    /// `der` or `raw`.
    pub signature_format: &'static str,
    /// The size of the signed data.
    pub data_bytes: usize,
    /// The certificate whose key was used.
    pub certificate: CertificateInfo,
}

/// The certificate of a [`SignatureCheck`].
#[derive(Serialize)]
pub struct CertificateInfo {
    /// Its subject.
    pub subject: String,
    /// The SHA-256 fingerprint.
    pub sha256: String,
    /// Its key.
    pub key: KeyInfo,
}

/// The key of a [`SignatureCheck`]'s certificate.
#[derive(Serialize)]
pub struct KeyInfo {
    /// E.g. `ECDSA brainpoolP256r1`.
    pub algorithm: String,
    /// Its standing under gemSpec_Krypt, e.g. `admissible`.
    pub status: &'static str,
}

/// Checks `signature` over `data` with `cert`'s key, ECDSA with SHA-256; the signature is
/// a DER `ECDSA-Sig-Value` or raw r‖s. `cert_name` and `signature_name` name the inputs
/// in errors.
///
/// # Errors
///
/// [`Error::SignatureMalformed`] for a signature in neither form,
/// [`Error::KeyUnsupported`] for a key without an ECDSA-SHA256 verifier.
pub fn verify_signature(
    cert: &Certificate,
    cert_name: &str,
    data: &[u8],
    signature: &[u8],
    signature_name: &str,
) -> Result<SignatureCheck, Error> {
    let (der, format) = normalize(signature, signature_name)?;
    let (status, algorithm) = classify_key(cert.public_key_info(), Timestamp::now());
    let verifier = algorithms::find(
        algorithms::DEFAULT,
        &cert.public_key_alg_id(),
        &ECDSA_WITH_SHA256,
    )
    .ok_or_else(|| {
        Error::KeyUnsupported(format!(
            "{cert_name}: no ECDSA-SHA256 verifier for a key of type {algorithm}"
        ))
    })?;
    let valid = verifier
        .verify_signature(cert.public_key(), data, &der)
        .is_ok();
    Ok(SignatureCheck {
        valid,
        hash: "SHA-256",
        signature_format: format,
        data_bytes: data.len(),
        certificate: CertificateInfo {
            subject: cert.subject().to_string(),
            sha256: cert.fingerprint_sha256(),
            key: KeyInfo {
                algorithm,
                status: status.as_str(),
            },
        },
    })
}

/// `signature` as a DER `ECDSA-Sig-Value`, and which form it came in.
fn normalize(signature: &[u8], name: &str) -> Result<(Vec<u8>, &'static str), Error> {
    if is_der_ecdsa_sig_value(signature) {
        return Ok((signature.to_vec(), "der"));
    }
    if signature.len() == 2 * COORDINATE {
        let (r, s) = signature.split_at(COORDINATE);
        return Ok((der_sig_value(r, s), "raw"));
    }
    Err(Error::SignatureMalformed(format!(
        "{name}: {} bytes, neither a DER ECDSA-Sig-Value nor r‖s of {} bytes",
        signature.len(),
        2 * COORDINATE
    )))
}

/// Whether `bytes` are exactly `SEQUENCE { INTEGER r, INTEGER s }`.
fn is_der_ecdsa_sig_value(bytes: &[u8]) -> bool {
    let Some((sequence, rest)) = tlv(0x30, bytes) else {
        return false;
    };
    if !rest.is_empty() {
        return false;
    }
    let Some((_, rest)) = tlv(0x02, sequence) else {
        return false;
    };
    matches!(tlv(0x02, rest), Some((_, rest)) if rest.is_empty())
}

/// The value of a DER element with `tag` at the start of `input`, and what follows;
/// short and one-byte long forms, which is all a signature needs.
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

/// `SEQUENCE { INTEGER r, INTEGER s }` from the unsigned big-endian `r` and `s`.
fn der_sig_value(r: &[u8], s: &[u8]) -> Vec<u8> {
    let r = der_integer(r);
    let s = der_integer(s);
    let mut out = vec![
        0x30,
        u8::try_from(r.len() + s.len()).expect("two 33-byte integers"),
    ];
    out.extend(r);
    out.extend(s);
    out
}

/// A DER INTEGER from an unsigned big-endian number: minimal, with a leading zero when
/// the top bit is set.
fn der_integer(n: &[u8]) -> Vec<u8> {
    let zeros = n.iter().take_while(|&&b| b == 0).count();
    let n = if zeros == n.len() {
        &n[n.len() - 1..]
    } else {
        &n[zeros..]
    };
    let mut out = vec![0x02];
    if n[0] & 0x80 != 0 {
        out.push(u8::try_from(n.len() + 1).expect("short"));
        out.push(0);
    } else {
        out.push(u8::try_from(n.len()).expect("short"));
    }
    out.extend_from_slice(n);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_becomes_minimal_der_and_der_is_recognised() {
        let mut r = vec![0x80];
        r.extend([0x11; 31]);
        let mut s = vec![0x00, 0x00];
        s.extend([0x22; 30]);
        let raw: Vec<u8> = r.iter().chain(&s).copied().collect();
        let (der, format) = normalize(&raw, "sig").unwrap();
        assert_eq!(format, "raw");
        assert!(is_der_ecdsa_sig_value(&der));
        // r gets its sign byte, s loses its leading zeros.
        assert_eq!(&der[..5], &[0x30, 2 + 33 + 2 + 30, 0x02, 33, 0x00]);
        // After the SEQUENCE header (2) and r's INTEGER (2 + 33): s's header.
        assert_eq!(der[2 + 2 + 33], 0x02);
        assert_eq!(der[2 + 2 + 33 + 1], 30);

        let (again, format) = normalize(&der, "sig").unwrap();
        assert_eq!((again, format), (der, "der"));

        assert!(normalize(&[1, 2, 3], "sig").is_err());
        assert!(
            normalize(&[0x30, 0x02, 0x02, 0x00], "sig").is_err(),
            "one integer only"
        );
    }
}
