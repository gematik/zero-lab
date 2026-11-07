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

//! PKCS#12 files written the way every current reader accepts them: DER, PBES2 AES-256,
//! an SHA-256 MAC, salts and IVs from the system's randomness.

use serde::Serialize;
use ti_pkcs12::{Pkcs12, Target};

use crate::error::Error;

/// How a file is encoded and protected.
#[derive(Serialize)]
pub struct Protection {
    /// `DER` or `BER`.
    pub encoding: &'static str,
    /// E.g. `SHA-256 × 2048`; absent without a MAC.
    pub mac: Option<String>,
    /// Distinct algorithms, e.g. `certificates: PBES2 AES-256-CBC`.
    pub encryption: Vec<String>,
}

/// What a PKCS#12 file holds and how it is protected.
pub struct Content {
    /// Its protection.
    pub protection: Protection,
    /// Its certificates.
    pub certificates: usize,
    /// Its keys.
    pub keys: usize,
}

/// A file re-encoded.
pub struct Converted {
    /// The new file.
    pub bytes: Vec<u8>,
    /// How the old file was protected.
    pub before: Protection,
}

/// The PKCS#12 file `bytes`, which `name` names, re-encoded under the same `password`.
///
/// # Errors
///
/// [`Error::Pkcs12`] for a file that does not open or does not encode,
/// [`Error::Randomness`] when the system has none to give.
pub fn convert(bytes: &[u8], name: &str, password: &str) -> Result<Converted, Error> {
    let p12 = decode(bytes, name, password)?;
    Ok(Converted {
        bytes: encode(&p12, password, name)?,
        before: protection(bytes, &p12),
    })
}

/// What the PKCS#12 file `bytes`, which `name` names, holds under `password`.
///
/// # Errors
///
/// [`Error::Pkcs12`] for a file that does not open.
pub fn content(bytes: &[u8], name: &str, password: &str) -> Result<Content, Error> {
    let p12 = decode(bytes, name, password)?;
    Ok(Content {
        protection: protection(bytes, &p12),
        certificates: p12.certificates.len(),
        keys: p12.keys.len(),
    })
}

fn decode(bytes: &[u8], name: &str, password: &str) -> Result<Pkcs12, Error> {
    ti_pkcs12::decode(bytes, password).map_err(|error| Error::Pkcs12 {
        source_name: name.to_owned(),
        source: error,
    })
}

/// `p12` encoded with `password`, salts and IVs from the system's randomness; `name`
/// names it in errors.
///
/// # Errors
///
/// [`Error::Pkcs12`] when it does not encode, [`Error::Randomness`] when the system has
/// no randomness to give.
pub fn encode(p12: &Pkcs12, password: &str, name: &str) -> Result<Vec<u8>, Error> {
    // Salt and IV for each key and the certificate safe, and the MAC salt.
    let mut pool = vec![0u8; 32 * (p12.keys.len() + 1) + 8];
    rustls::crypto::ring::default_provider()
        .secure_random
        .fill(&mut pool)
        .map_err(|_| Error::Randomness)?;
    let mut offset = 0;
    ti_pkcs12::encode(p12, password, |buf: &mut [u8]| {
        buf.copy_from_slice(&pool[offset..offset + buf.len()]);
        offset += buf.len();
    })
    .map_err(|error| Error::Pkcs12 {
        source_name: name.to_owned(),
        source: error,
    })
}

fn protection(bytes: &[u8], p12: &Pkcs12) -> Protection {
    let mut encryption: Vec<String> = Vec::new();
    for e in &p12.encryption {
        let target = if e.target == Target::Key {
            "key"
        } else {
            "certificates"
        };
        let entry = format!("{target}: {}", e.algorithm);
        if !encryption.contains(&entry) {
            encryption.push(entry);
        }
    }
    Protection {
        encoding: if bytes.get(1) == Some(&0x80) {
            "BER"
        } else {
            "DER"
        },
        mac: p12
            .mac
            .as_ref()
            .map(|mac| format!("{} × {}", mac.digest, mac.iterations)),
        encryption,
    }
}
