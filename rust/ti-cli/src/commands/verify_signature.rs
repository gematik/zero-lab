//! `ti pki verify-signature`: an ECDSA-SHA256 signature over a file, checked against a
//! certificate's key with ti-pki's verifiers. An ePA client checks the VAU's
//! `signed_pub_keys` this way; the certificate's own standing is `pki verify`'s job.

use serde::Serialize;
use sha2::{Digest, Sha256};
use ti_pki::Certificate;
use ti_pki::key::classify_key;
use ti_pki::load::SystemClock;
use ti_pki::{Clock, algorithms};

use crate::cli::VerifySignatureArgs;
use crate::error::{CliError, Exit};
use crate::input;
use crate::output::{Document, Line, Output, SCHEMA, Tone, hex};

/// DER contents of the `ecdsa-with-SHA256` AlgorithmIdentifier (RFC 5758 §3.2: no
/// parameters), the form [`algorithms::find`] takes.
const ECDSA_WITH_SHA256: [u8; 10] = [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];

/// The coordinate size of the curves identities sign with.
const COORDINATE: usize = 32;

/// The JSON document.
#[derive(Serialize)]
struct Report {
    schema: u32,
    valid: bool,
    hash: &'static str,
    /// `der` or `raw`.
    signature_format: &'static str,
    data_bytes: usize,
    certificate: CertificateInfo,
}

#[derive(Serialize)]
struct CertificateInfo {
    subject: String,
    sha256: String,
    key: KeyInfo,
}

#[derive(Serialize)]
struct KeyInfo {
    algorithm: String,
    status: &'static str,
}

/// Runs `ti pki verify-signature`.
pub fn run(args: &VerifySignatureArgs, out: &Output) -> Result<Exit, CliError> {
    let source = input::read(&args.cert)?;
    let cert = input::certificates(&source, "00")?.remove(0).certificate;
    let data = input::read(&args.data)?;
    let signature = input::read(&args.signature)?;
    let (der, format) = normalize(&signature.bytes, &signature.name)?;
    let (status, algorithm) = classify_key(cert.public_key_info(), SystemClock.now());
    let verifier = algorithms::find(
        algorithms::DEFAULT,
        &cert.public_key_alg_id(),
        &ECDSA_WITH_SHA256,
    )
    .ok_or_else(|| {
        CliError::KeyUnsupported(format!(
            "{}: no ECDSA-SHA256 verifier for a key of type {algorithm}",
            source.name
        ))
    })?;
    let valid = verifier
        .verify_signature(cert.public_key(), &data.bytes, &der)
        .is_ok();
    let report = Report {
        schema: SCHEMA,
        valid,
        hash: "SHA-256",
        signature_format: format,
        data_bytes: data.bytes.len(),
        certificate: CertificateInfo {
            subject: cert.subject().to_string(),
            sha256: fingerprint(&cert),
            key: KeyInfo {
                algorithm,
                status: status.as_str(),
            },
        },
    };
    if out.is_json() {
        out.json(&report)?;
    } else {
        let mut doc = Document::default();
        doc.field(
            "signature",
            if valid {
                Line::status(Tone::Good, "valid")
            } else {
                Line::status(Tone::Bad, "not valid")
            }
            .and_dim(format!(
                " · {} over {} bytes, {}",
                report.hash, report.data_bytes, format
            )),
        );
        doc.field("signer", Line::text(&report.certificate.subject));
        doc.field("key", Line::text(&report.certificate.key.algorithm));
        out.render(&doc)?;
    }
    Ok(if valid { Exit::Ok } else { Exit::Invalid })
}

fn fingerprint(cert: &Certificate) -> String {
    hex(&Sha256::digest(cert.der()))
}

/// `signature` as a DER `ECDSA-Sig-Value`, and which form it came in.
fn normalize(signature: &[u8], name: &str) -> Result<(Vec<u8>, &'static str), CliError> {
    if is_der_ecdsa_sig_value(signature) {
        return Ok((signature.to_vec(), "der"));
    }
    if signature.len() == 2 * COORDINATE {
        let (r, s) = signature.split_at(COORDINATE);
        return Ok((der_sig_value(r, s), "raw"));
    }
    Err(CliError::SignatureMalformed(format!(
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
