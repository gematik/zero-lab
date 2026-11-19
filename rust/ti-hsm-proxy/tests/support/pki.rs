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

//! A CA and certificates made in the test, keys included: no private key stands in a
//! fixture. ECDSA P-256 throughout.

#![allow(dead_code, reason = "each test binary uses a part of the helpers")]

use std::str::FromStr as _;
use std::time::{Duration, SystemTime};

use der::asn1::{Ia5String, OctetString};
use der::{Encode as _, EncodePem as _};
use p256::ecdsa::{DerSignature, SigningKey};
use p256::pkcs8::EncodePrivateKey as _;
use x509_cert::Certificate;
use x509_cert::TbsCertificate;
use x509_cert::builder::profile::BuilderProfile;
use x509_cert::builder::{Builder as _, CertificateBuilder};
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::{
    BasicConstraints, ExtendedKeyUsage, KeyUsage, KeyUsages, SubjectAltName,
};
use x509_cert::ext::{Extension, ToExtension as _};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::{SubjectPublicKeyInfoOwned, SubjectPublicKeyInfoRef};
use x509_cert::time::{Time, Validity};

/// A certificate with its key, both PEM.
pub struct Issued {
    pub cert: String,
    pub key: String,
}

/// A CA that issues for the test.
pub struct Ca {
    key: SigningKey,
    name: Name,
    pub cert: String,
}

struct Profile {
    issuer: Name,
    subject: Name,
    ca: bool,
    names: Vec<GeneralName>,
}

impl BuilderProfile for Profile {
    fn get_issuer(&self, _: &Name) -> Name {
        self.issuer.clone()
    }

    fn get_subject(&self) -> Name {
        self.subject.clone()
    }

    fn build_extensions(
        &self,
        _: SubjectPublicKeyInfoRef<'_>,
        _: SubjectPublicKeyInfoRef<'_>,
        tbs: &TbsCertificate,
    ) -> x509_cert::builder::Result<Vec<Extension>> {
        let subject = tbs.subject();
        let mut extensions = vec![
            BasicConstraints {
                ca: self.ca,
                path_len_constraint: None,
            }
            .to_extension(subject, &[])?,
        ];
        if self.ca {
            extensions.push(
                KeyUsage(KeyUsages::KeyCertSign | KeyUsages::CRLSign).to_extension(subject, &[])?,
            );
        } else {
            extensions
                .push(KeyUsage(KeyUsages::DigitalSignature.into()).to_extension(subject, &[])?);
            extensions.push(
                ExtendedKeyUsage(vec![
                    const_oid::db::rfc5280::ID_KP_SERVER_AUTH,
                    const_oid::db::rfc5280::ID_KP_CLIENT_AUTH,
                ])
                .to_extension(subject, &[])?,
            );
            extensions.push(SubjectAltName(self.names.clone()).to_extension(subject, &[])?);
        }
        Ok(extensions)
    }
}

fn new_key() -> SigningKey {
    loop {
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes).unwrap();
        if let Ok(key) = SigningKey::from_slice(&bytes) {
            return key;
        }
    }
}

fn serial() -> SerialNumber {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).unwrap();
    bytes[0] &= 0x7f;
    SerialNumber::new(&bytes).unwrap()
}

fn pem(cert: &Certificate) -> String {
    cert.to_pem(der::pem::LineEnding::LF).unwrap()
}

fn key_pem(key: &SigningKey) -> String {
    let der = key.to_pkcs8_der().unwrap();
    pem_rfc7468::encode_string("PRIVATE KEY", pem_rfc7468::LineEnding::LF, der.as_bytes()).unwrap()
}

/// Valid from an hour ago for `days`.
pub fn valid_for(days: u64) -> Validity {
    let now = SystemTime::now();
    Validity::new(
        Time::try_from(now - Duration::from_hours(1)).unwrap(),
        Time::try_from(now + Duration::from_hours(days * 24)).unwrap(),
    )
}

/// Valid two days ago, expired yesterday.
pub fn expired() -> Validity {
    let now = SystemTime::now();
    Validity::new(
        Time::try_from(now - Duration::from_hours(48)).unwrap(),
        Time::try_from(now - Duration::from_hours(24)).unwrap(),
    )
}

/// A DNS name for a subjectAltName.
pub fn dns(name: &str) -> GeneralName {
    GeneralName::DnsName(Ia5String::new(name).unwrap())
}

/// A URI, such as a SPIFFE ID, for a subjectAltName.
pub fn uri(uri: &str) -> GeneralName {
    GeneralName::UniformResourceIdentifier(Ia5String::new(uri).unwrap())
}

/// The address 127.0.0.1 for a subjectAltName.
pub fn loopback() -> GeneralName {
    GeneralName::IpAddress(OctetString::new(vec![127, 0, 0, 1]).unwrap())
}

impl Ca {
    /// A self-signed CA, TEST-ONLY.
    pub fn new(name: &str) -> Ca {
        let key = new_key();
        let name = Name::from_str(&format!("CN={name} TEST-ONLY")).unwrap();
        let profile = Profile {
            issuer: name.clone(),
            subject: name.clone(),
            ca: true,
            names: Vec::new(),
        };
        let spki = SubjectPublicKeyInfoOwned::from_key(key.verifying_key()).unwrap();
        let cert = CertificateBuilder::new(profile, serial(), valid_for(30), spki)
            .unwrap()
            .build::<_, DerSignature>(&key)
            .unwrap();
        Ca {
            cert: pem(&cert),
            key,
            name,
        }
    }

    /// An end-entity certificate for `names`, valid as `validity` says.
    pub fn issue(&self, cn: &str, names: Vec<GeneralName>, validity: Validity) -> Issued {
        let key = new_key();
        let profile = Profile {
            issuer: self.name.clone(),
            subject: Name::from_str(&format!("CN={cn} TEST-ONLY")).unwrap(),
            ca: false,
            names,
        };
        let spki = SubjectPublicKeyInfoOwned::from_key(key.verifying_key()).unwrap();
        let cert = CertificateBuilder::new(profile, serial(), validity, spki)
            .unwrap()
            .build::<_, DerSignature>(&self.key)
            .unwrap();
        let _ = cert.to_der().unwrap();
        Issued {
            cert: pem(&cert),
            key: key_pem(&key),
        }
    }
}
