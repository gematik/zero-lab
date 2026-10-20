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

//! Where versions of ti before the shared store kept their state. The store's own paths
//! are spec/store's (STORE-092), resolved in [`crate::store::profile`].

use std::path::PathBuf;

use crate::error::CliError;

/// The folder all TI tools share, and this tool's name within it.
const GROUP: &str = "telematik";
const TOOL: &str = "ti";

/// Where versions before the store kept TSL state and comfort IDs: read once, to move
/// them into the profile's state.
pub fn legacy_state_dir() -> Result<PathBuf, CliError> {
    default_state_base().map(|base| base.join(GROUP).join(TOOL))
}

#[cfg(windows)]
fn default_state_base() -> Result<PathBuf, CliError> {
    default_cache_base().map(|base| base.join("state"))
}

#[cfg(not(windows))]
fn default_state_base() -> Result<PathBuf, CliError> {
    if let Some(xdg) = std::env::var_os("XDG_STATE_HOME").map(PathBuf::from)
        && xdg.is_absolute()
    {
        return Ok(xdg);
    }
    std::env::home_dir()
        .filter(|home| home.is_absolute())
        .map(|home| home.join(".local").join("state"))
        .ok_or(CliError::CacheDir("no home directory"))
}

#[cfg(windows)]
fn default_cache_base() -> Result<PathBuf, CliError> {
    std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .ok_or(CliError::CacheDir("LOCALAPPDATA is not set"))
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    #[test]
    fn legacy_state_ends_in_the_tool_folder() {
        if let Ok(dir) = legacy_state_dir() {
            assert!(
                dir.ends_with(Path::new("telematik").join("ti")),
                "{}",
                dir.display()
            );
        }
    }
}
