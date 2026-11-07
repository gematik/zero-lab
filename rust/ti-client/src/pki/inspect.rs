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

//! What the TI reads from a certificate, without validating it; and the path to a
//! trusted root the trust material on hand suggests for it.

use core::fmt::Write as _;

use der::asn1::ObjectIdentifier;
use serde::Serialize;
use ti_pki::key::classify_key;
use ti_pki::model;
use ti_pki::{Certificate, Env, Timestamp};

use super::verify::environment;
use crate::client::Client;
use crate::error::Error;
use crate::files::Dirs;
use crate::input::{self, Loaded};
use crate::trust::{Session, Warning};

/// The certificates of an input and, for a PKCS#12 file, its container.
#[derive(Serialize)]
pub struct Inspection {
    /// The input's name, e.g. its file.
    pub source: String,
    /// The certificates, those with their key first.
    pub certificates: Vec<CertificateInfo>,
    /// The container, when the input is a PKCS#12 file.
    pub pkcs12: Option<Pkcs12Info>,
}

/// What a PKCS#12 container says beyond its certificates.
#[derive(Serialize)]
pub struct Pkcs12Info {
    /// `DER`, or `BER` as Java keystores and card vendors write it.
    pub encoding: &'static str,
    /// Its MAC; absent without one.
    pub mac: Option<MacInfo>,
    /// The encryption of each encrypted safe and shrouded key, in file order.
    pub encryption: Vec<EncryptionInfo>,
    /// Its keys.
    pub keys: Vec<P12KeyInfo>,
}

/// An encrypted safe or shrouded key.
#[derive(Serialize)]
pub struct EncryptionInfo {
    /// `certificates` (an encrypted safe) or `key` (a shrouded key).
    pub target: &'static str,
    /// E.g. `PBES2 AES-256-CBC`.
    pub algorithm: String,
}

/// A PKCS#12 MAC.
#[derive(Serialize)]
pub struct MacInfo {
    /// E.g. `SHA-256`.
    pub digest: String,
    /// Its iteration count.
    pub iterations: u32,
}

/// A key of a PKCS#12 file.
#[derive(Serialize)]
pub struct P12KeyInfo {
    /// `EC`, `RSA`, or the algorithm OID.
    pub algorithm: String,
    /// The named curve of an EC key, e.g. `brainpoolP256r1`.
    pub curve: Option<String>,
    /// The `friendlyName` of its bag.
    pub friendly_name: Option<String>,
    /// The `localKeyId` of its bag, lower-case hex.
    pub local_key_id: Option<String>,
    /// Index into `certificates` of the certificate this key belongs to.
    pub certificate: Option<usize>,
}

/// A certificate as `ti_pki::model` describes it, with what a PKCS#12 file adds.
#[derive(Clone, Debug, Serialize)]
pub struct CertificateInfo {
    /// The certificate.
    #[serde(flatten)]
    pub info: model::Certificate,
    /// The input is a PKCS#12 file that also holds this certificate's private key.
    pub private_key: bool,
    /// The `friendlyName` of its bag, in a PKCS#12 file.
    pub friendly_name: Option<String>,
    /// The `localKeyId` of its bag, in a PKCS#12 file.
    pub local_key_id: Option<String>,
}

impl core::ops::Deref for CertificateInfo {
    type Target = model::Certificate;

    fn deref(&self) -> &Self::Target {
        &self.info
    }
}

/// The certificates in `bytes`, which `name` names, described at `now`; a PKCS#12 file is
/// opened with `p12_password`.
///
/// # Errors
///
/// As [`input::load`].
pub fn inspect(
    bytes: &[u8],
    name: &str,
    p12_password: &str,
    now: Timestamp,
) -> Result<(Inspection, Vec<Certificate>), Error> {
    let input = input::load(bytes, name, p12_password)?;
    let certificates: Vec<CertificateInfo> = input
        .certificates
        .iter()
        .map(|loaded| describe(loaded, now))
        .collect();
    let pkcs12 = input
        .pkcs12
        .as_ref()
        .map(|p12| container(bytes, p12, &certificates));
    let certs = input
        .certificates
        .into_iter()
        .map(|loaded| loaded.certificate)
        .collect();
    Ok((
        Inspection {
            source: name.to_owned(),
            certificates,
            pkcs12,
        },
        certs,
    ))
}

/// `certificates`, which `source` names, described at `now`.
pub fn describe_all(source: String, certificates: Vec<Certificate>, now: Timestamp) -> Inspection {
    Inspection {
        source,
        certificates: certificates
            .into_iter()
            .map(|certificate| describe(&Loaded::without_key(certificate), now))
            .collect(),
        pkcs12: None,
    }
}

/// `loaded` described at `now`.
pub fn describe(loaded: &Loaded, now: Timestamp) -> CertificateInfo {
    let (friendly_name, local_key_id) = loaded.bag.as_ref().map_or((None, None), |(name, id)| {
        (name.clone(), id.as_deref().map(hex_id))
    });
    CertificateInfo {
        info: model::Certificate::new(&loaded.certificate, now),
        private_key: loaded.private_key,
        friendly_name,
        local_key_id,
    }
}

/// The paths to a trusted root the trust material on hand suggests for some
/// certificates.
pub struct Paths {
    /// The environment the certificates show, if they show one.
    pub env: Option<Env>,
    /// Whether a TSL was cached, so that its CAs are known.
    pub tsl_loaded: bool,
    /// Per certificate, its path upwards and whether it reaches a root.
    pub chains: Vec<(Vec<Certificate>, bool)>,
}

/// For each of `certs`, the path to a trusted root as the trust material suggests it:
/// built from the cache or the embedded roots (never the network), the other
/// certificates of the input and the TSL's CAs, by name and key identifier only. Nothing
/// is validated; [`super::verify`] does that. Without a cached TSL its CAs are unknown,
/// so an issuer that is missing then is not loaded rather than untrusted
/// ([`Paths::tsl_loaded`]); without `dirs` there is no trust material on hand at all.
/// `warn` hears what the session tells as it opens.
pub fn paths(
    client: &Client,
    dirs: Option<&Dirs>,
    certs: &[Certificate],
    now: Timestamp,
    warn: impl Fn(Warning),
) -> Paths {
    let env = environment(None, certs, now).ok().map(|(env, _)| env);
    let material = env.and_then(|env| {
        let session = Session::new(client, dirs?, true, warn).ok()?;
        let config = ti_pki::TrustConfig::preset(env);
        session.load(&config, env.tier(), None).ok()
    });
    let tsl_loaded = material.as_ref().is_some_and(|m| m.info.tsl.is_some());
    let store = material.map(|m| m.store);
    let chains = certs
        .iter()
        .map(|cert| {
            let others: Vec<Certificate> = certs
                .iter()
                .filter(|c| c.der() != cert.der())
                .chain(store.iter().flat_map(|s| s.intermediates()))
                .cloned()
                .collect();
            let built = store
                .as_deref()
                .map(|store| ti_pki::chain::build_chain(cert, &others, store));
            match built {
                Some(Ok(chain)) => (chain, true),
                Some(Err(e)) => (e.partial, false),
                None => (vec![cert.clone()], false),
            }
        })
        .collect();
    Paths {
        env,
        tsl_loaded,
        chains,
    }
}

/// The key of `cert` in words, e.g. `ECDSA brainpoolP256r1`.
pub fn key_algorithm(cert: &Certificate, now: Timestamp) -> String {
    classify_key(cert.public_key_info(), now).1
}

/// What the PKCS#12 container says beyond its certificates: encoding, protection, and
/// its keys with the certificate each belongs to.
fn container(bytes: &[u8], p12: &ti_pkcs12::Pkcs12, certs: &[CertificateInfo]) -> Pkcs12Info {
    let keys = p12
        .keys
        .iter()
        .map(|key| {
            let (algorithm, curve) = key
                .algorithm()
                .map_or((String::from("unknown"), None), |(a, c)| {
                    (algorithm_name(&a), c.map(|c| curve_name(&c)))
                });
            let local_key_id = key.local_key_id.as_deref().map(hex_id);
            P12KeyInfo {
                algorithm,
                curve,
                friendly_name: key.friendly_name.clone(),
                certificate: local_key_id.as_ref().and_then(|id| {
                    certs
                        .iter()
                        .position(|c| c.local_key_id.as_ref() == Some(id))
                }),
                local_key_id,
            }
        })
        .collect();
    Pkcs12Info {
        encoding: if bytes.get(1) == Some(&0x80) {
            "BER"
        } else {
            "DER"
        },
        mac: p12.mac.as_ref().map(|mac| MacInfo {
            digest: mac.digest.clone(),
            iterations: mac.iterations,
        }),
        encryption: p12
            .encryption
            .iter()
            .map(|e| EncryptionInfo {
                target: if e.target == ti_pkcs12::Target::Key {
                    "key"
                } else {
                    "certificates"
                },
                algorithm: e.algorithm.clone(),
            })
            .collect(),
        keys,
    }
}

/// `localKeyId`s are opaque bytes; lower-case hex without separators, as OpenSSL
/// prints them compactly.
fn hex_id(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut hex, b| {
        let _ = write!(hex, "{b:02x}");
        hex
    })
}

fn algorithm_name(oid: &ObjectIdentifier) -> String {
    match oid.to_string().as_str() {
        "1.2.840.10045.2.1" => "EC".to_owned(),
        "1.2.840.113549.1.1.1" => "RSA".to_owned(),
        other => other.to_owned(),
    }
}

fn curve_name(oid: &ObjectIdentifier) -> String {
    match oid.to_string().as_str() {
        "1.3.36.3.3.2.8.1.1.7" => "brainpoolP256r1".to_owned(),
        "1.3.36.3.3.2.8.1.1.11" => "brainpoolP384r1".to_owned(),
        "1.3.36.3.3.2.8.1.1.13" => "brainpoolP512r1".to_owned(),
        "1.2.840.10045.3.1.7" => "P-256".to_owned(),
        "1.3.132.0.34" => "P-384".to_owned(),
        "1.3.132.0.35" => "P-521".to_owned(),
        other => other.to_owned(),
    }
}
