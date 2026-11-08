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

//! The roots an environment trusts, as the A_28419 walk from the embedded anchor through
//! roots.json yields them.

use serde::Serialize;
use ti_pki::{Certificate, Env, Timestamp, TrustConfig};

use super::bundle::Found;
use super::inspect::key_algorithm;
use crate::error::Error;
use crate::trust::{Session, TrustInfo};

/// The roots of an environment.
#[derive(Serialize)]
pub struct Roots {
    /// E.g. `prod`.
    pub environment: &'static str,
    /// The trust material they come from.
    pub trust: TrustInfo,
    /// Downloads skipped the TLS check ([`crate::Net::insecure`]).
    pub insecure_transport: bool,
    /// The roots, in the order the walk reached them.
    pub roots: Vec<RootInfo>,
}

/// A root.
#[derive(Serialize)]
pub struct RootInfo {
    /// Its common name.
    pub common_name: String,
    /// Its subject.
    pub subject: String,
    /// Its `notBefore`, RFC 3339.
    pub not_before: String,
    /// Its `notAfter`, RFC 3339.
    pub not_after: String,
    /// [`RootInfo::not_after`] as a timestamp.
    #[serde(skip)]
    pub not_after_at: Timestamp,
    /// `valid`, `expired` or `not_yet_valid`, now.
    pub validity: &'static str,
    /// The embedded anchor the walk started from.
    pub anchor: bool,
    /// The key, e.g. `ECDSA brainpoolP256r1`.
    pub key: String,
    /// The SHA-256 fingerprint.
    pub sha256: String,
    /// The certificate.
    pub pem: String,
}

/// The roots `env` trusts at `at` or now; with `nist_only`, those a client without
/// brainpool can use.
///
/// # Errors
///
/// Those of [`Session::load_env`].
pub fn list(
    session: &Session,
    env: Env,
    nist_only: bool,
    at: Option<Timestamp>,
) -> Result<Roots, Error> {
    let (config, material) = session.load_env(env, nist_only, at)?;
    let now = at.unwrap_or_else(Timestamp::now);
    Ok(Roots {
        environment: env.as_str(),
        roots: material
            .store
            .roots()
            .iter()
            .map(|root| describe(root, &config, now))
            .collect(),
        trust: material.info,
        insecure_transport: session.insecure,
    })
}

/// The roots of [`list`] as a bundle's certificates, oldest generation first.
///
/// # Errors
///
/// Those of [`Session::load_env`].
pub fn bundle(
    session: &Session,
    env: Env,
    nist_only: bool,
    at: Option<Timestamp>,
) -> Result<Found, Error> {
    let (_, material) = session.load_env(env, nist_only, at)?;
    let mut certificates = material.store.roots().to_vec();
    certificates.sort_by_key(|root| generation(root.subject_cn()));
    Ok(Found {
        environment: env.as_str(),
        certificates,
        tsl_sequence_number: None,
        trust: material.info,
        insecure_transport: session.insecure,
    })
}

fn describe(root: &Certificate, config: &TrustConfig, now: Timestamp) -> RootInfo {
    RootInfo {
        common_name: root.subject_cn().to_owned(),
        subject: root.subject().to_string(),
        not_before: root.not_before().to_string(),
        not_after: root.not_after().to_string(),
        not_after_at: root.not_after(),
        validity: ti_pki::model::validity(root, now),
        anchor: root.der() == &*config.anchor,
        key: key_algorithm(root, now),
        sha256: root.fingerprint_sha256(),
        pem: root.to_pem(),
    }
}

/// The name with its first number as a number, so `RCA10` sorts after `RCA9`.
pub fn generation(name: &str) -> (String, u64, String) {
    let start = name
        .find(|c: char| c.is_ascii_digit())
        .unwrap_or(name.len());
    let digits = name[start..]
        .find(|c: char| !c.is_ascii_digit())
        .map_or(name.len(), |n| start + n);
    (
        name[..start].to_owned(),
        name[start..digits].parse().unwrap_or(0),
        name[digits..].to_owned(),
    )
}
