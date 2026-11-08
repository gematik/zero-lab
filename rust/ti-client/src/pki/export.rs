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

//! A server's trust material as one bundle file, which a CronJob puts into a ConfigMap or
//! a volume and an operator carries to an air-gapped site. The bytes are handed out only
//! once a load of those very bytes has verified them, the way a consumer will.

use serde::Serialize;
use ti_pki::load::{Bundle, ReloadOutcome, ReloadPolicy, Reloader, StaticLoader};
use ti_pki::revocation::RevocationStatus;
use ti_pki::{Env, Timestamp, TrustConfig};

use crate::block_on;
use crate::error::Error;
use crate::trust::Session;

/// What fits a ConfigMap: its limit of 1 MiB, less room for the object's own fields.
const CONFIG_MAP_ROOM: usize = 1_000_000;

/// A verified trust bundle.
pub struct TrustBundle {
    /// The bundle file's bytes.
    pub bytes: Vec<u8>,
    /// What it holds.
    pub info: BundleInfo,
}

/// What a trust bundle holds.
#[derive(Serialize)]
pub struct BundleInfo {
    /// E.g. `prod`.
    pub environment: &'static str,
    /// Its label: the environment and when the set was fetched.
    pub label: String,
    /// The TSL's sequence number.
    pub sequence_number: Option<u64>,
    /// The TSL's `NextUpdate`, RFC 3339.
    pub next_update: Option<String>,
    /// [`BundleInfo::next_update`] as a timestamp.
    #[serde(skip)]
    pub next_update_ts: Option<Timestamp>,
    /// What the set says of the TSL signer; absent if it holds no current status.
    pub signer_status: Option<&'static str>,
    /// When the set was fetched; what its age is measured from.
    pub fetched_at: String,
    /// [`BundleInfo::fetched_at`] as a timestamp.
    #[serde(skip)]
    pub fetched_at_ts: Option<Timestamp>,
    /// Its size.
    pub bytes: usize,
    /// False: use a volume, a ConfigMap cannot hold it.
    pub fits_config_map: bool,
}

/// `env`'s trust material as a bundle, verified at `at` or now as a consumer will.
///
/// # Errors
///
/// [`Error::Trust`] for a preset its tier does not admit; those of [`Session::load`] and
/// [`Session::verified_set`]; [`Error::TrustLoad`] when the bundle does not verify.
pub fn trust_bundle(
    session: &Session,
    env: Env,
    at: Option<Timestamp>,
) -> Result<TrustBundle, Error> {
    let config = TrustConfig::preset(env);
    config.validate(env.tier()).map_err(Error::Trust)?;
    let loaded = session.load(&config, env.tier(), at)?;
    let material = session.verified_set(&config, &loaded, at)?.set;
    let label = format!("{env} {}", material.fetched_at);
    let bytes = Bundle::new(&config, label.clone(), material).to_vec();

    let consumer = Bundle::from_slice(&bytes)
        .and_then(|bundle| StaticLoader::from_bundle(bundle, &config))
        .map_err(|e| Error::TrustLoad(e.to_string()))?;
    let reloader = Reloader::new(
        config,
        env.tier(),
        consumer,
        move || at.unwrap_or_else(Timestamp::now),
        ReloadPolicy::default(),
    )
    .map_err(Error::Trust)?;
    match block_on(reloader.tick()) {
        ReloadOutcome::Swapped { .. } => {}
        other => return Err(Error::TrustLoad(format!("the set: {other:?}"))),
    }
    let status = reloader.handle().status();
    let info = BundleInfo {
        environment: env.as_str(),
        label,
        sequence_number: status.tsl_state.as_ref().map(|s| s.sequence_number),
        next_update: status.tsl_next_update.map(|t| t.to_string()),
        next_update_ts: status.tsl_next_update,
        signer_status: status.tsl_signer_status.map(RevocationStatus::as_str),
        fetched_at: status.fetched_at.map(|t| t.to_string()).unwrap_or_default(),
        fetched_at_ts: status.fetched_at,
        bytes: bytes.len(),
        fits_config_map: bytes.len() <= CONFIG_MAP_ROOM,
    };
    Ok(TrustBundle { bytes, info })
}
