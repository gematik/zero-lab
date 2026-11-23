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
    let all: Vec<Certificate> = input
        .certificates
        .iter()
        .map(|loaded| loaded.certificate.clone())
        .collect();
    let ti = shows_ti(&all, now);
    let certificates: Vec<CertificateInfo> = input
        .certificates
        .iter()
        .map(|loaded| describe_under(loaded, now, KeyRule::of(&loaded.certificate, ti)))
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
    let ti = shows_ti(&certificates, now);
    Inspection {
        source,
        certificates: certificates
            .into_iter()
            .map(|certificate| {
                let rule = KeyRule::of(&certificate, ti);
                describe_under(&Loaded::without_key(certificate), now, rule)
            })
            .collect(),
        pkcs12: None,
    }
}

/// The rule a certificate's key is rated by in its description.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyRule {
    /// VALID-002, gemSpec_Krypt's tables: a TI certificate.
    Ti,
    /// The TLS profile `web` of `spec/pki-validation`: TLSV-041 for an end entity, TLSV-042
    /// for a CA. A certificate outside the TI is held to it, never to the TI's tables.
    Web,
}

impl KeyRule {
    /// `cert`'s rule when nothing judged it under a profile: the TI's when it carries a TI
    /// type or `ti_input` (the certificates it came with show a TI environment), else the
    /// web's. A TI CA carries no type of its own, so the input's environment decides for it.
    pub fn of(cert: &Certificate, ti_input: bool) -> KeyRule {
        if ti_input || ti_pki::detect_certificate_type(cert).is_some() {
            KeyRule::Ti
        } else {
            KeyRule::Web
        }
    }
}

/// Whether `certs` show a TI environment, by the detection `pki verify` uses.
fn shows_ti(certs: &[Certificate], now: Timestamp) -> bool {
    environment(None, certs, now).is_ok()
}

/// `loaded` described at `now`, its key rated by VALID-002.
pub fn describe(loaded: &Loaded, now: Timestamp) -> CertificateInfo {
    describe_under(loaded, now, KeyRule::Ti)
}

/// `loaded` described at `now`, its key rated by `rule`.
pub fn describe_under(loaded: &Loaded, now: Timestamp, rule: KeyRule) -> CertificateInfo {
    let (friendly_name, local_key_id) = loaded.bag.as_ref().map_or((None, None), |(name, id)| {
        (name.clone(), id.as_deref().map(hex_id))
    });
    let mut info = model::Certificate::new(&loaded.certificate, now);
    if rule == KeyRule::Web {
        let cert = &loaded.certificate;
        let (status, rule) = ti_tls::web::key_status(cert.public_key_info(), cert.is_ca());
        info.key.status = status.as_str();
        info.key.rule = rule;
    }
    CertificateInfo {
        info,
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

#[cfg(test)]
mod tests {
    use rustls_pki_types::CertificateDer;
    use ti_tls::{Offline, WebCheck};

    use super::*;

    /// 2026-01-01, when the corpus's certificates and OCSP responses were made for.
    const AT: Timestamp = Timestamp(1_767_225_600);

    fn corpus(name: &str) -> Vec<u8> {
        let path = format!(
            "{}/../../spec/pki-validation/testdata/{name}",
            env!("CARGO_MANIFEST_DIR")
        );
        std::fs::read(path).unwrap()
    }

    fn der(name: &str) -> Vec<u8> {
        pem_rfc7468::decode_vec(&corpus(name)).unwrap().1
    }

    /// TLSV-041: a web end entity's key line says what its verdict says, an ECDSA P-384 key
    /// admissible and an RSA 2048 key phased out (`key_phased_out`), rated by TLSV-041 and
    /// not by VALID-002, which calls P-384 not admissible.
    #[test]
    fn tlsv_041_the_key_line_of_a_web_certificate_agrees_with_its_verdict() {
        let check = WebCheck::new([CertificateDer::from(der("web-root.pem"))]);
        for (leaf, status, warnings) in [
            ("web-p384", "admissible", &[][..]),
            ("web-rsa2048", "phased out", &["key_phased_out"][..]),
        ] {
            let chain = [
                CertificateDer::from(der(&format!("{leaf}.pem"))),
                CertificateDer::from(der("web-ca.pem")),
            ];
            let stapled = corpus(&format!("ocsp/{leaf}-good.der"));
            let verdict =
                crate::block_on(check.verify(&chain, "www.web.test", Some(&stapled), AT, &Offline));
            assert!(verdict.is_valid(), "{leaf}: {}", verdict.detail);
            assert_eq!(verdict.warnings, warnings, "{leaf}");

            let certs: Vec<Certificate> = chain
                .iter()
                .map(|c| Certificate::from_der(c).unwrap())
                .collect();
            // The corpus names carry TEST-ONLY, which environment detection reads as the TI's
            // test environment; a real web certificate does not, and has no TI type.
            let rule = KeyRule::of(&certs[0], false);
            assert_eq!(rule, KeyRule::Web, "{leaf}");
            let line = describe_under(&Loaded::without_key(certs[0].clone()), AT, rule);
            assert_eq!(
                (line.key.status, line.key.rule),
                (status, "TLSV-041"),
                "{leaf}"
            );
            let ca = describe_under(&Loaded::without_key(certs[1].clone()), AT, rule);
            assert_eq!((ca.key.status, ca.key.rule), ("admissible", "TLSV-042"));
        }
        let p384 = Certificate::from_der(&der("web-p384.pem")).unwrap();
        let ti = describe(&Loaded::without_key(p384), AT);
        assert_eq!(
            (ti.key.status, ti.key.rule),
            ("not admissible", "VALID-002")
        );
    }

    /// VALID-002: a TI certificate's key line keeps gemSpec_Krypt's tables, brainpoolP256r1
    /// admissible, whichever certificate of a TI input it is.
    #[test]
    fn valid_002_a_ti_certificate_is_rated_by_the_ti_tables() {
        let certs: Vec<Certificate> = ["ti-good.pem", "ti-ca.pem"]
            .iter()
            .map(|name| Certificate::from_der(&der(name)).unwrap())
            .collect();
        let inspection = describe_all("ti".into(), certs, AT);
        for cert in &inspection.certificates {
            assert_eq!(cert.key.rule, "VALID-002", "{}", cert.subject);
        }
    }
}
