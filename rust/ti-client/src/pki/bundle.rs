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

//! Verified certificates as a CA bundle, the input other tools take for trust: PEM, what
//! curl `--cacert`, openssl `-CAfile`, Go and rustls read; or a PKCS#12 truststore for
//! Java, each certificate a `trustedCertEntry` (the bag attributes OpenSSL's `-caname` and
//! `-jdktrust anyExtendedKeyUsage` write).

use ti_pkcs12::{CertificateBag, Pkcs12, oids};
use ti_pki::Certificate;

use crate::error::Error;
use crate::trust::TrustInfo;

/// What a bundle takes, before it is written.
pub struct Found {
    /// E.g. `prod`.
    pub environment: &'static str,
    /// The certificates, in bundle order.
    pub certificates: Vec<Certificate>,
    /// The sequence number of the TSL the CAs come from, if they come from one.
    pub tsl_sequence_number: Option<u64>,
    /// The trust material they come from.
    pub trust: TrustInfo,
    /// Downloads skipped the TLS check ([`crate::Net::insecure`]).
    pub insecure_transport: bool,
}

/// `certificates` as PEM, one after another.
pub fn pem(certificates: &[Certificate]) -> Vec<u8> {
    certificates
        .iter()
        .map(Certificate::to_pem)
        .collect::<String>()
        .into_bytes()
}

/// Java's alias of each certificate: its common name in lower case, as keytool shows
/// aliases, made unique with `-2`, `-3`, … in order.
pub fn aliases(certificates: &[Certificate]) -> Vec<String> {
    let mut taken: Vec<String> = Vec::with_capacity(certificates.len());
    for certificate in certificates {
        let base = certificate.subject_cn().to_lowercase();
        let mut alias = base.clone();
        let mut n = 2;
        while taken.contains(&alias) {
            alias = format!("{base}-{n}");
            n += 1;
        }
        taken.push(alias);
    }
    taken
}

/// `certificates` as a PKCS#12 truststore under `aliases`, protected with `password`.
///
/// # Errors
///
/// As [`crate::pkcs12::encode`].
pub fn truststore(
    certificates: &[Certificate],
    aliases: &[String],
    password: &str,
) -> Result<Vec<u8>, Error> {
    let p12 = Pkcs12 {
        certificates: certificates
            .iter()
            .zip(aliases)
            .map(|(certificate, alias)| CertificateBag {
                der: certificate.der().to_vec(),
                friendly_name: Some(alias.clone()),
                local_key_id: None,
                trusted_key_usage: Some(oids::ANY_EXTENDED_KEY_USAGE),
            })
            .collect(),
        ..Pkcs12::default()
    };
    crate::pkcs12::encode(&p12, password, "truststore")
}
