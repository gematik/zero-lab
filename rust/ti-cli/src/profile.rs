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

//! The profile in effect and the directories its files live in.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use crate::cli::GlobalArgs;
use crate::error::CliError;
use crate::files::is_name_byte;
use crate::paths;

const GROUP: &str = "telematik";
const TOOL: &str = "ti";

/// The profile in effect and the directories its files live in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Profile {
    /// `None` when no profile was asked for: the directories are then the bases.
    pub name: Option<String>,
    pub state_dir: PathBuf,
    pub cache_dir: PathBuf,
}

struct Inputs<'a> {
    profile: Option<&'a str>,
    state_dir: Option<PathBuf>,
    cache_dir: Option<PathBuf>,
}

impl Profile {
    /// `--profile`, else `TI_PROFILE`; `TI_STATE_DIR` and `--cache-dir` (`TI_CACHE_DIR`)
    /// override the bases.
    ///
    /// # Errors
    ///
    /// `arguments_invalid` for a name or a directory outside the rules, or when a base
    /// has to be derived and the platform has no home for it.
    pub fn resolve(global: &GlobalArgs) -> Result<Self, CliError> {
        let env_profile = env_text("TI_PROFILE")?;
        let env_state = non_empty(std::env::var_os("TI_STATE_DIR")).map(PathBuf::from);
        resolve_from(
            Inputs {
                profile: global.profile.as_deref().or(env_profile.as_deref()),
                state_dir: env_state,
                cache_dir: global.cache_dir.clone(),
            },
            paths::state_home,
            paths::cache_home,
        )
    }
}

fn env_text(key: &str) -> Result<Option<String>, CliError> {
    non_empty(std::env::var_os(key))
        .map(|v| {
            v.into_string()
                .map_err(|_| CliError::Arguments(format!("{key} is not UTF-8")))
        })
        .transpose()
}

/// An empty variable counts as unset, as a shell's `VAR=` is usually meant.
fn non_empty(value: Option<OsString>) -> Option<OsString> {
    value.filter(|v| !v.is_empty())
}

fn resolve_from(
    at: Inputs<'_>,
    state_home: impl FnOnce() -> Result<PathBuf, CliError>,
    cache_home: impl FnOnce() -> Result<PathBuf, CliError>,
) -> Result<Profile, CliError> {
    if let Some(name) = at.profile {
        validate_name(name)?;
    }
    let state = base(at.state_dir, "TI_STATE_DIR", state_home)?;
    let cache = base(at.cache_dir, "--cache-dir", cache_home)?;
    let below = |base: PathBuf| match at.profile {
        Some(name) => base.join("profiles").join(name),
        None => base,
    };
    Ok(Profile {
        name: at.profile.map(str::to_owned),
        state_dir: below(state),
        cache_dir: below(cache),
    })
}

fn base(
    over: Option<PathBuf>,
    what: &str,
    home: impl FnOnce() -> Result<PathBuf, CliError>,
) -> Result<PathBuf, CliError> {
    match over {
        Some(dir) if Path::new(&dir).is_absolute() => Ok(dir),
        Some(dir) => Err(CliError::Arguments(format!(
            "{what} must be an absolute path, not {}",
            dir.display()
        ))),
        None => Ok(home()?.join(GROUP).join(TOOL)),
    }
}

/// A profile name is a single path component the tool can use as it is; no name is
/// reserved.
///
/// # Errors
///
/// `arguments_invalid` unless the name is 1 to 64 characters of `A-Z a-z 0-9 . _ -` and
/// does not start with a dot.
pub fn validate_name(name: &str) -> Result<(), CliError> {
    let ok =
        (1..=64).contains(&name.len()) && !name.starts_with('.') && name.bytes().all(is_name_byte);
    if ok {
        Ok(())
    } else {
        Err(CliError::Arguments(format!(
            "profile name {name:?} must be 1 to 64 characters of A-Z a-z 0-9 . _ - and not start with a dot"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dirs(
        name: Option<&str>,
        state: Option<&str>,
        cache: Option<&str>,
    ) -> Result<Profile, CliError> {
        let at = Inputs {
            profile: name,
            state_dir: state.map(PathBuf::from),
            cache_dir: cache.map(PathBuf::from),
        };
        resolve_from(
            at,
            || Ok(PathBuf::from("/h/state")),
            || Ok(PathBuf::from("/h/cache")),
        )
    }

    #[test]
    fn no_profile_uses_the_bases() {
        let p = dirs(None, None, None).unwrap();
        assert_eq!(p.name, None);
        assert_eq!(p.state_dir, PathBuf::from("/h/state/telematik/ti"));
        assert_eq!(p.cache_dir, PathBuf::from("/h/cache/telematik/ti"));
        let p = dirs(None, Some("/s"), Some("/c")).unwrap();
        assert_eq!(p.state_dir, PathBuf::from("/s"));
        assert_eq!(p.cache_dir, PathBuf::from("/c"));
    }

    #[test]
    fn a_profile_is_a_directory_below_the_bases() {
        let p = dirs(Some("work"), Some("/s"), None).unwrap();
        assert_eq!(p.name.as_deref(), Some("work"));
        assert_eq!(p.state_dir, PathBuf::from("/s/profiles/work"));
        assert_eq!(
            p.cache_dir,
            PathBuf::from("/h/cache/telematik/ti/profiles/work")
        );
    }

    #[test]
    fn a_name_with_a_path_separator_is_refused() {
        for name in ["../x", "a/b", "a\\b", "", ".x", &"a".repeat(65), "a b"] {
            assert!(validate_name(name).is_err(), "{name:?}");
            assert!(dirs(Some(name), None, None).is_err(), "{name:?}");
        }
    }

    #[test]
    fn default_and_fresh_are_ordinary_names() {
        for name in ["default", "fresh", "a.b_c-1", &"a".repeat(64)] {
            assert!(validate_name(name).is_ok(), "{name:?}");
        }
        let p = dirs(Some("default"), Some("/s"), Some("/c")).unwrap();
        assert_eq!(p.state_dir, PathBuf::from("/s/profiles/default"));
    }

    #[test]
    fn a_relative_state_dir_is_refused() {
        assert!(dirs(None, Some("state"), None).is_err());
        assert!(dirs(None, None, Some("cache")).is_err());
    }
}
