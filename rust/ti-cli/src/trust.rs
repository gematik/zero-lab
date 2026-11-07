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

//! The trust material session of a command: ti-client's, over the profile's directories
//! and the HTTP options, with its warnings on stderr.

pub use ti_client::trust::Session;
use ti_client::trust::Warning;

use crate::cli::GlobalArgs;
use crate::error::CliError;
use crate::http;
use crate::output::{self, Output};
use crate::profile::Profile;

/// A session for `global`'s profile and HTTP options; with `offline`, no request is ever
/// made. Warns on stderr when `-k` is in effect or the cache cannot be opened.
pub fn session(global: &GlobalArgs, offline: bool, out: &Output) -> Result<Session, CliError> {
    let profile = Profile::resolve(global)?;
    let client = http::client(&global.net, out.verbosity());
    Ok(Session::new(&client, &profile.dirs(), offline, warn)?)
}

/// A session's warning on stderr.
pub fn warn(warning: Warning) {
    match warning {
        Warning::MemoryCache { dir, reason } => output::warning(format_args!(
            "cache {}: {reason}; caching in memory only",
            dir.display()
        )),
        Warning::Insecure => {
            output::warning("-k: the TLS certificates of download servers are not checked");
        }
    }
}
