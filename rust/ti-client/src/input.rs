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

//! Certificates from the bytes of an input: PEM, DER or PKCS#12.

use ti_pki::Certificate;

use crate::error::Error;

/// A certificate from the input, and whether the input also holds its private key.
pub struct Loaded {
    /// The certificate.
    pub certificate: Certificate,
    /// The input is a PKCS#12 file with this certificate's key.
    pub private_key: bool,
    /// Its bag in a PKCS#12 file: `friendlyName` and `localKeyId`.
    pub bag: Option<(Option<String>, Option<Vec<u8>>)>,
}

impl Loaded {
    /// `certificate` as read from a file without keys.
    pub fn without_key(certificate: Certificate) -> Loaded {
        Loaded {
            certificate,
            private_key: false,
            bag: None,
        }
    }
}

/// Everything read from an input.
pub struct Input {
    /// The certificates, those with their key first.
    pub certificates: Vec<Loaded>,
    /// The decoded file, when the input is PKCS#12; its certificates are in
    /// [`Input::certificates`] too.
    pub pkcs12: Option<ti_pkcs12::Pkcs12>,
}

/// The certificates in `bytes`, which `name` names in errors: every CERTIFICATE block of a
/// PEM file, one DER certificate, or the certificates of a PKCS#12 file decoded with
/// `p12_password`. Of a PKCS#12 file, the certificates with their key come first: they are
/// the identity, the others its chain.
///
/// # Errors
///
/// As [`load`].
pub fn certificates(bytes: &[u8], name: &str, p12_password: &str) -> Result<Vec<Loaded>, Error> {
    Ok(load(bytes, name, p12_password)?.certificates)
}

/// [`certificates`], and for PKCS#12 input the decoded file.
///
/// # Errors
///
/// [`Error::Pkcs12`] for a PKCS#12 file that does not open, [`Error::Certificate`] for a
/// certificate that does not parse, [`Error::NoCertificate`] for an input without any.
pub fn load(bytes: &[u8], name: &str, p12_password: &str) -> Result<Input, Error> {
    let certificate_error = |error| Error::Certificate {
        source_name: name.to_owned(),
        source: error,
    };
    let mut pkcs12 = None;
    let certs: Vec<Loaded> = if ti_pkcs12::is_pkcs12(bytes) {
        let p12 = ti_pkcs12::decode(bytes, p12_password).map_err(|error| Error::Pkcs12 {
            source_name: name.to_owned(),
            source: error,
        })?;
        let paired: Vec<usize> = p12.pairs().iter().map(|pair| pair.certificate).collect();
        let mut order: Vec<usize> = paired.clone();
        order.extend((0..p12.certificates.len()).filter(|i| !paired.contains(i)));
        let certs = order
            .into_iter()
            .map(|i| {
                let bag = &p12.certificates[i];
                Ok(Loaded {
                    certificate: Certificate::from_der(&bag.der).map_err(certificate_error)?,
                    private_key: paired.contains(&i),
                    bag: Some((bag.friendly_name.clone(), bag.local_key_id.clone())),
                })
            })
            .collect::<Result<_, Error>>()?;
        pkcs12 = Some(p12);
        certs
    } else if bytes.windows(11).any(|w| w == b"-----BEGIN ") {
        ti_pki::parse_pem_certificates(bytes)
            .map_err(certificate_error)?
            .into_iter()
            .map(Loaded::without_key)
            .collect()
    } else if bytes.is_empty() {
        Vec::new()
    } else {
        vec![Loaded::without_key(
            Certificate::from_der(bytes).map_err(certificate_error)?,
        )]
    };
    if certs.is_empty() {
        return Err(Error::NoCertificate {
            source_name: name.to_owned(),
        });
    }
    Ok(Input {
        certificates: certs,
        pkcs12,
    })
}
