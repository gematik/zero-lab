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

//! `ti profile list|delete`: the profiles in use, each a directory below `profiles/` in
//! the state and the cache base.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::cli::{GlobalArgs, ProfileCommand};
use crate::error::{CliError, Exit};
use crate::output::{Document, Line, Output, SCHEMA};
use crate::profile::{Bases, Profile, validate_name};

#[derive(Serialize)]
struct ListedProfile {
    /// `None` for the unnamed location: the bases themselves.
    name: Option<String>,
    state: String,
    cache: String,
    /// The size of the files below the state directory; 0 if it does not exist.
    state_bytes: u64,
    cache_bytes: u64,
}

#[derive(Serialize)]
struct ListReport {
    schema: u32,
    profiles: Vec<ListedProfile>,
}

/// The directories of `name` below `base`; the base itself without a name.
fn below(base: &Path, name: Option<&str>) -> PathBuf {
    match name {
        Some(name) => base.join("profiles").join(name),
        None => base.to_path_buf(),
    }
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
                .filter(|name| validate_name(name).is_ok())
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

fn listed(bases: &Bases, name: Option<&str>) -> ListedProfile {
    let (state, cache) = (below(&bases.state, name), below(&bases.cache, name));
    let skip = name.is_none().then_some("profiles");
    ListedProfile {
        name: name.map(str::to_owned),
        state_bytes: size(&state, skip),
        cache_bytes: size(&cache, skip),
        state: state.display().to_string(),
        cache: cache.display().to_string(),
    }
}

/// `ti profile list`.
pub fn list(global: &GlobalArgs, out: &Output) -> Result<Exit, CliError> {
    let bases = Profile::bases(global)?;
    let names: BTreeSet<String> = names_in(&bases.state)
        .union(&names_in(&bases.cache))
        .cloned()
        .collect();
    let report = ListReport {
        schema: SCHEMA,
        profiles: std::iter::once(None)
            .chain(names.iter().map(|n| Some(n.as_str())))
            .map(|name| listed(&bases, name))
            .collect(),
    };
    if out.is_json() {
        out.json(&report)?;
        return Ok(Exit::Ok);
    }
    let mut doc = Document::default();
    doc.section("Profiles");
    let kib = |bytes: u64| Line::text(format!("{} KiB", bytes.div_ceil(1024)));
    doc.table(
        &["profile", "state", "cache"],
        report
            .profiles
            .iter()
            .map(|p| {
                let name = p.name.as_deref().map_or(Line::dim("(none)"), Line::text);
                vec![name, kib(p.state_bytes), kib(p.cache_bytes)]
            })
            .collect(),
    );
    out.render(&doc)?;
    Ok(Exit::Ok)
}

#[derive(Serialize)]
struct DeleteReport {
    schema: u32,
    profile: String,
    /// The directories removed, the state's first.
    removed: Vec<String>,
}

/// Removes `dir`, which a profile name put below `profiles/`. A symlink is removed
/// itself, never its target. `false` when there was nothing of that name.
fn remove_profile_dir(dir: &Path) -> Result<bool, CliError> {
    let fail = |e: std::io::Error| CliError::State {
        path: dir.display().to_string(),
        reason: format!("cannot remove it: {e}"),
    };
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

/// `ti profile delete NAME --yes`: `<state base>/profiles/NAME` and
/// `<cache base>/profiles/NAME`; the name is validated first, so that it cannot leave
/// `profiles/`.
pub fn delete(global: &GlobalArgs, name: &str, yes: bool, out: &Output) -> Result<Exit, CliError> {
    validate_name(name)?;
    if !yes {
        return Err(CliError::Arguments(format!(
            "deleting profile {name} removes its state and cache, with the TSL state and \
             comfort IDs in them: pass --yes"
        )));
    }
    let bases = Profile::bases(global)?;
    let mut removed = Vec::new();
    for dir in [
        below(&bases.state, Some(name)),
        below(&bases.cache, Some(name)),
    ] {
        if remove_profile_dir(&dir)? {
            removed.push(dir.display().to_string());
        }
    }
    if removed.is_empty() {
        return Err(CliError::Arguments(format!(
            "no profile {name}: `ti profile list` shows the profiles"
        )));
    }
    let report = DeleteReport {
        schema: SCHEMA,
        profile: name.to_owned(),
        removed,
    };
    if out.is_json() {
        out.json(&report)?;
    } else {
        let mut doc = Document::default();
        doc.section(format!("Profile {} deleted", report.profile));
        for path in &report.removed {
            doc.field("removed", Line::code(path));
        }
        out.render(&doc)?;
    }
    Ok(Exit::Ok)
}

/// `ti profile …`.
pub fn run(command: &ProfileCommand, global: &GlobalArgs, out: &Output) -> Result<Exit, CliError> {
    match command {
        ProfileCommand::List => list(global, out),
        ProfileCommand::Delete { name, yes } => delete(global, name, *yes, out),
    }
}
