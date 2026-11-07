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

//! The profiles' directories: a named profile's state and cache are `profiles/NAME`
//! below the bases, the unnamed location the bases themselves. Which bases and which
//! name are in effect is the front end's configuration.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::error::Error;
use crate::files::{Dirs, is_plain_name};

/// The directories the profiles live below.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bases {
    /// Of the state files.
    pub state: PathBuf,
    /// Of the cache files.
    pub cache: PathBuf,
}

impl Bases {
    /// The directories of the profile `name`; the bases themselves without one.
    pub fn dirs(&self, name: Option<&str>) -> Dirs {
        Dirs {
            state: below(&self.state, name),
            cache: below(&self.cache, name),
        }
    }
}

/// `name` below `base`; the base itself without a name.
fn below(base: &Path, name: Option<&str>) -> PathBuf {
    match name {
        Some(name) => base.join("profiles").join(name),
        None => base.to_path_buf(),
    }
}

/// A profile name is a single path component used as it is; no name is reserved.
///
/// # Errors
///
/// [`Error::Refused`] unless the name is 1 to 64 characters of `A-Z a-z 0-9 . _ -` and
/// does not start with a dot.
pub fn validate_name(name: &str) -> Result<(), Error> {
    if is_plain_name(name) {
        Ok(())
    } else {
        Err(Error::Refused(format!(
            "profile name {name:?} must be 1 to 64 characters of A-Z a-z 0-9 . _ - and not start with a dot"
        )))
    }
}

/// A profile in use.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Listed {
    /// `None` for the unnamed location: the bases themselves.
    pub name: Option<String>,
    /// Its state directory.
    pub state: String,
    /// Its cache directory.
    pub cache: String,
    /// The size of the files below the state directory; 0 if it does not exist.
    pub state_bytes: u64,
    /// The size of the files below the cache directory.
    pub cache_bytes: u64,
}

/// The unnamed location and every profile with a directory below either base.
pub fn list(bases: &Bases) -> Vec<Listed> {
    let names: BTreeSet<String> = names_in(&bases.state)
        .union(&names_in(&bases.cache))
        .cloned()
        .collect();
    std::iter::once(None)
        .chain(names.iter().map(|n| Some(n.as_str())))
        .map(|name| listed(bases, name))
        .collect()
}

/// The profile names with a directory in `base`; entries that are not directories or
/// whose name the rules refuse are not profiles.
fn names_in(base: &Path) -> BTreeSet<String> {
    std::fs::read_dir(base.join("profiles"))
        .map(|entries| {
            entries
                .flatten()
                .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
                .filter_map(|e| e.file_name().into_string().ok())
                .filter(|name| is_plain_name(name))
                .collect()
        })
        .unwrap_or_default()
}

/// The size of the files below `dir`, symlinks not followed; `skip` is left out at the
/// top, so that the unnamed location does not count the profiles below it.
fn size(dir: &Path, skip: Option<&str>) -> u64 {
    std::fs::read_dir(dir).map_or(0, |entries| {
        entries
            .flatten()
            .filter(|e| skip.is_none_or(|skip| e.file_name() != skip))
            .map(|e| match e.file_type() {
                Ok(t) if t.is_dir() => size(&e.path(), None),
                Ok(t) if t.is_file() => e.metadata().map_or(0, |m| m.len()),
                _ => 0,
            })
            .sum()
    })
}

fn listed(bases: &Bases, name: Option<&str>) -> Listed {
    let dirs = bases.dirs(name);
    let skip = name.is_none().then_some("profiles");
    Listed {
        name: name.map(str::to_owned),
        state_bytes: size(&dirs.state, skip),
        cache_bytes: size(&dirs.cache, skip),
        state: dirs.state.display().to_string(),
        cache: dirs.cache.display().to_string(),
    }
}

/// Removes the state and the cache of the profile `name`, the TSL state and comfort IDs
/// among them; the name is validated first, so that it cannot leave `profiles/`. Returns
/// the directories removed, the state's first: none when there was no such profile.
///
/// # Errors
///
/// [`Error::Refused`] for a name outside the rules; [`Error::State`] or [`Error::Cache`]
/// for a directory that cannot be removed.
pub fn delete(bases: &Bases, name: &str) -> Result<Vec<PathBuf>, Error> {
    validate_name(name)?;
    let dirs = bases.dirs(Some(name));
    let state_failed: fn(String, String) -> Error = |path, reason| Error::State { path, reason };
    let cache_failed: fn(String, String) -> Error = |path, reason| Error::Cache { path, reason };
    let mut removed = Vec::new();
    for (dir, failed) in [(dirs.state, state_failed), (dirs.cache, cache_failed)] {
        if remove_profile_dir(&dir, failed)? {
            removed.push(dir);
        }
    }
    Ok(removed)
}

/// Removes `dir`, which a profile name put below `profiles/`. A symlink is removed
/// itself, never its target. `false` when there was nothing of that name. `failed` makes
/// the error of the base `dir` is in.
fn remove_profile_dir(dir: &Path, failed: fn(String, String) -> Error) -> Result<bool, Error> {
    let fail =
        |e: std::io::Error| failed(dir.display().to_string(), format!("cannot remove it: {e}"));
    let meta = match std::fs::symlink_metadata(dir) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(fail(e)),
    };
    if meta.is_dir() {
        std::fs::remove_dir_all(dir).map_err(fail)?;
    } else if meta.file_type().is_symlink() {
        // A directory symlink on Windows is removed as a directory.
        std::fs::remove_file(dir)
            .or_else(|_| std::fs::remove_dir(dir))
            .map_err(fail)?;
    } else {
        return Ok(false);
    }
    Ok(true)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    fn temp(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("ti-client-profile-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_profile_symlink_is_removed_never_its_target() {
        let root = temp("symlink");
        let bases = Bases {
            state: root.join("state"),
            cache: root.join("cache"),
        };
        let target = root.join("elsewhere");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(target.join("keep"), "x").unwrap();
        std::fs::create_dir_all(bases.state.join("profiles")).unwrap();
        std::os::unix::fs::symlink(&target, bases.state.join("profiles/work")).unwrap();
        let removed = delete(&bases, "work").unwrap();
        assert_eq!(removed, [bases.state.join("profiles/work")]);
        assert!(target.join("keep").exists());
        assert_eq!(delete(&bases, "work").unwrap(), Vec::<PathBuf>::new());
        assert!(matches!(delete(&bases, "../x"), Err(Error::Refused(_))));
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn the_unnamed_location_does_not_count_the_profiles_below_it() {
        let root = temp("list");
        let bases = Bases {
            state: root.join("state"),
            cache: root.join("cache"),
        };
        std::fs::create_dir_all(bases.state.join("profiles/work")).unwrap();
        std::fs::write(bases.state.join("profiles/work/f"), [0; 10]).unwrap();
        std::fs::write(bases.state.join("top"), [0; 3]).unwrap();
        std::fs::create_dir_all(bases.cache.join("profiles/.hidden")).unwrap();
        let listed = list(&bases);
        assert_eq!(listed.len(), 2, "{listed:?}");
        assert_eq!(
            (listed[0].name.as_deref(), listed[0].state_bytes),
            (None, 3)
        );
        assert_eq!(
            (listed[1].name.as_deref(), listed[1].state_bytes),
            (Some("work"), 10)
        );
        std::fs::remove_dir_all(&root).unwrap();
    }
}
