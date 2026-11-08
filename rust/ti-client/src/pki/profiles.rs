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

//! `pki profiles`: the validation profiles, what each requires of the certificate types it
//! accepts, and which CAs of an environment's verified TSL may issue them.

use serde::Serialize;
use ti_pki::model::{TslCas, TypeRequirements, ValidationProfile};
use ti_pki::profile::{PROFILES, Profile};
use ti_pki::{Env, TrustConfig};

use crate::error::Error;
use crate::trust::Session;

/// Every validation profile.
pub fn list() -> Vec<ValidationProfile> {
    PROFILES.iter().map(|p| ValidationProfile::new(p)).collect()
}

/// A profile described.
#[derive(Clone, Debug, Serialize)]
pub struct Description {
    /// The profile.
    pub profile: ValidationProfile,
    /// The baseline each accepted type imposes, with the profile's overlay applied.
    pub types: Vec<TypeRequirements>,
    /// With an environment: the CAs whose TSL entry allows one of the profile's types.
    pub tsl: Option<TslCas>,
}

/// `profile` described; with `env`, the CAs of `env`'s verified TSL that may issue its
/// types, from the session `open` makes.
///
/// # Errors
///
/// [`Error::Trust`] for a preset outside its tier; the session's errors; and
/// [`Error::TrustLoad`] when there is no verified TSL, offline and nothing cached.
pub fn describe<E: From<Error>>(
    profile: &Profile,
    env: Option<Env>,
    open: impl FnOnce() -> Result<Session, E>,
) -> Result<Description, E> {
    let tsl = env.map(|env| tsl_cas(profile, env, open)).transpose()?;
    Ok(Description {
        profile: ValidationProfile::new(profile),
        types: profile
            .accepts_types
            .iter()
            .map(|t| TypeRequirements::new(profile, *t))
            .collect(),
        tsl,
    })
}

fn tsl_cas<E: From<Error>>(
    profile: &Profile,
    env: Env,
    open: impl FnOnce() -> Result<Session, E>,
) -> Result<TslCas, E> {
    let config = TrustConfig::preset(env);
    config.validate(env.tier()).map_err(Error::Trust)?;
    let session = open()?;
    let store = session.load(&config, env.tier(), None)?.store;
    if !store.has_tsl_types() {
        return Err(Error::TrustLoad(
            "no verified TSL: offline and nothing cached; run once without --offline".into(),
        )
        .into());
    }
    Ok(TslCas::new(&store, profile, env))
}
