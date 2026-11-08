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

//! The `.kon` files: found, listed, selected and read the way the Go `ti` does, sharing
//! its files; written atomically with mode 0600. What a file may hold is
//! [`ti_connector_client::edit`]'s.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use serde::Serialize;
use ti_connector_client::Dotkon;

use crate::error::Error;

/// `$XDG_CONFIG_HOME/telematik/connectors`, or `~/.config/…` on every platform, as the
/// Go `ti` has it.
pub fn connectors_dir() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(|| std::env::home_dir().map(|home| home.join(".config")))?;
    Some(base.join("telematik").join("connectors"))
}

/// The file the selected name is kept in.
pub fn active_file() -> Option<PathBuf> {
    connectors_dir().map(|dir| dir.join("active"))
}

/// Where the name of the configuration to use came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    /// The caller named it.
    Explicit,
    /// The active selection ([`select`]).
    Active,
    /// Neither: `default`.
    Default,
}

/// The configuration to use: `explicit` unless empty, else the active selection, else
/// `default`; with where the choice came from.
pub fn selected(explicit: Option<&str>) -> (String, Source) {
    if let Some(name) = explicit.filter(|n| !n.is_empty()) {
        return (name.to_owned(), Source::Explicit);
    }
    let active = active_file()
        .and_then(|file| std::fs::read_to_string(file).ok())
        .map(|name| name.trim().to_owned())
        .filter(|name| !name.is_empty());
    match active {
        Some(name) => (name, Source::Active),
        None => ("default".to_owned(), Source::Default),
    }
}

/// The file of configuration `name`: a path as given (with or without `.kon`), else
/// `NAME`, `NAME.kon` in the current directory, then in [`connectors_dir`].
///
/// # Errors
///
/// [`Error::ConnectorConfig`] naming where it looked.
pub fn resolve(name: &str) -> Result<PathBuf, Error> {
    let name = match name.strip_prefix("~/") {
        Some(rest) => std::env::home_dir().map_or_else(|| PathBuf::from(name), |h| h.join(rest)),
        None => PathBuf::from(name),
    };
    let with_ext = |p: &Path| {
        let mut p = p.as_os_str().to_owned();
        p.push(".kon");
        PathBuf::from(p)
    };
    let mut candidates = vec![name.clone(), with_ext(&name)];
    let is_path = name.is_absolute() || name.components().count() > 1;
    if !is_path && let Some(dir) = connectors_dir() {
        candidates.push(with_ext(&dir.join(&name)));
        candidates.push(dir.join(&name));
    }
    candidates.into_iter().find(|c| c.is_file()).ok_or_else(|| {
        let searched = connectors_dir()
            .filter(|_| !is_path)
            .map(|dir| format!(" (searched the current directory and {})", dir.display()))
            .unwrap_or_default();
        Error::ConnectorConfig(format!(
            "connector configuration {:?} not found{searched}",
            name.display().to_string()
        ))
    })
}

/// Reads and validates the `.kon` file at `path`.
///
/// # Errors
///
/// [`Error::ConnectorConfig`].
pub fn read(path: &Path) -> Result<Dotkon, Error> {
    let bytes = std::fs::read(path)
        .map_err(|e| Error::ConnectorConfig(format!("{}: {e}", path.display())))?;
    Dotkon::parse(&bytes).map_err(|e| Error::ConnectorConfig(format!("{}: {e}", path.display())))
}

/// A `.kon` file as read from disk.
#[derive(Clone, Debug)]
pub struct KonFile {
    /// The name it was selected by.
    pub name: String,
    /// Where it is.
    pub path: PathBuf,
    /// Its content.
    pub json: Vec<u8>,
    /// Its permission bits, where the platform has them.
    pub mode: Option<u32>,
}

impl KonFile {
    /// The file of configuration `name` ([`resolve`]), unparsed.
    ///
    /// # Errors
    ///
    /// [`Error::ConnectorConfig`].
    pub fn read(name: &str) -> Result<KonFile, Error> {
        let path = resolve(name)?;
        let json = std::fs::read(&path)
            .map_err(|e| Error::ConnectorConfig(format!("{}: {e}", path.display())))?;
        Ok(KonFile {
            name: name.to_owned(),
            mode: mode(&path),
            path,
            json,
        })
    }
}

/// The permission bits of `path`; `None` where the platform has none or it cannot be
/// read.
#[cfg(unix)]
pub fn mode(path: &Path) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::metadata(path).ok().map(|m| m.permissions().mode())
}

/// The permission bits of `path`; `None` where the platform has none or it cannot be
/// read.
#[cfg(not(unix))]
pub fn mode(_: &Path) -> Option<u32> {
    None
}

/// The configurations there are.
#[derive(Debug, Serialize)]
pub struct Listing {
    /// The configuration used when none is named.
    pub selected: String,
    /// The `.kon` files of the current directory, then of [`connectors_dir`].
    pub configurations: Vec<Configuration>,
}

/// A `.kon` file found.
#[derive(Debug, Serialize)]
pub struct Configuration {
    /// Its name: the file name without `.kon`.
    pub name: String,
    /// Where it is.
    pub path: String,
    /// The Konnektor's address.
    pub url: Option<String>,
    /// `mandant/workplace/client system`.
    pub context: Option<String>,
    /// Why the file cannot be used.
    pub error: Option<String>,
}

/// The `.kon` files of the current directory and of [`connectors_dir`], each read, with
/// the one [`selected`] for `explicit`.
pub fn list(explicit: Option<&str>) -> Listing {
    let mut paths: Vec<PathBuf> = Vec::new();
    for dir in [Some(PathBuf::from(".")), connectors_dir()]
        .into_iter()
        .flatten()
    {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        let mut found: Vec<PathBuf> = entries
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.is_file() && p.extension().is_some_and(|e| e == "kon"))
            .collect();
        found.sort();
        paths.extend(found);
    }
    let configurations = paths
        .into_iter()
        .map(|path| {
            let kon = read(&path);
            Configuration {
                name: path
                    .file_stem()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .into_owned(),
                path: path.display().to_string(),
                url: kon.as_ref().ok().map(|k| k.url.clone()),
                context: kon
                    .as_ref()
                    .ok()
                    .map(|k| format!("{}/{}/{}", k.mandant_id, k.workplace_id, k.client_system_id)),
                error: kon.err().map(|e| e.to_string()),
            }
        })
        .collect();
    Listing {
        selected: selected(explicit).0,
        configurations,
    }
}

/// The configuration selected.
#[derive(Debug, Serialize)]
pub struct Selection {
    /// Its name.
    pub name: String,
    /// Its file.
    pub path: String,
}

/// Makes `name` the active selection, after checking that its file is valid.
///
/// # Errors
///
/// [`Error::ConnectorConfig`] for a configuration not found or not valid, or without a
/// home directory; [`Error::Write`].
pub fn select(name: &str) -> Result<Selection, Error> {
    let path = resolve(name)?;
    read(&path)?;
    let file = active_file().ok_or_else(|| {
        Error::ConnectorConfig("no home directory for the active selection".into())
    })?;
    let write = || -> std::io::Result<()> {
        if let Some(dir) = file.parent() {
            std::fs::create_dir_all(dir)?;
        }
        std::fs::write(&file, format!("{name}\n"))
    };
    write().map_err(|e| write_error(&file, &e))?;
    Ok(Selection {
        name: name.to_owned(),
        path: path.display().to_string(),
    })
}

/// Where a new configuration `name` is written: a path as given (`.kon` added), a bare
/// name in [`connectors_dir`].
///
/// # Errors
///
/// [`Error::ConnectorConfig`] without a home directory for a bare name.
pub fn new_path(name: &str) -> Result<PathBuf, Error> {
    let with_ext = if Path::new(name).extension().is_some_and(|e| e == "kon") {
        name.to_owned()
    } else {
        format!("{name}.kon")
    };
    let path = Path::new(&with_ext);
    if path.is_absolute() || path.components().count() > 1 || with_ext == name {
        return Ok(path.to_owned());
    }
    connectors_dir()
        .map(|dir| dir.join(&with_ext))
        .ok_or_else(|| {
            Error::ConnectorConfig("no home directory for the connectors directory".into())
        })
}

/// A hidden file next to `path` for `what`, unique to this process.
fn sibling(path: &Path, what: &str) -> PathBuf {
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    path.with_file_name(format!(".{name}.{what}-{}", std::process::id()))
}

fn write_error(path: &Path, e: &std::io::Error) -> Error {
    Error::Write(std::io::Error::new(
        e.kind(),
        format!("{}: {e}", path.display()),
    ))
}

/// Writes a new file only its owner can read, failing if it exists.
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

/// A copy of `json` to edit, next to `path` and only its owner's, so the file itself is
/// replaced only by a valid copy ([`write()`]). The caller removes it ([`remove_copy`]).
///
/// # Errors
///
/// [`Error::Write`].
pub fn editable_copy(path: &Path, json: &[u8]) -> Result<PathBuf, Error> {
    let copy = sibling(path, "edit");
    write_private(&copy, json).map_err(|e| write_error(&copy, &e))?;
    Ok(copy)
}

/// Removes the copy [`editable_copy`] made; one already gone, or one that cannot be
/// removed, is left as it is: the file itself is unchanged either way.
pub fn remove_copy(copy: &Path) {
    let _ = std::fs::remove_file(copy);
}

/// Reads the copy [`editable_copy`] made.
///
/// # Errors
///
/// [`Error::Write`], as the copy is the caller's output.
pub fn read_copy(copy: &Path) -> Result<Vec<u8>, Error> {
    std::fs::read(copy).map_err(|e| write_error(copy, &e))
}

/// Replaces `path` atomically by a file with mode 0600, creating its directory with
/// mode 0700; a directory others may read adds a warning to `warnings`.
///
/// # Errors
///
/// [`Error::Write`].
pub fn write(path: &Path, json: &[u8], warnings: &mut Vec<String>) -> Result<(), Error> {
    let dir = path
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    if !dir.exists() {
        std::fs::create_dir_all(dir).map_err(|e| write_error(dir, &e))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
                .map_err(|e| write_error(dir, &e))?;
        }
    } else if mode(dir).is_some_and(|m| m & 0o077 != 0) {
        warnings.push(format!(
            "{}: others may list the directory; chmod 700 it",
            dir.display()
        ));
    }
    let temporary = sibling(path, "new");
    let written = write_private(&temporary, json).and_then(|()| std::fs::rename(&temporary, path));
    if let Err(e) = written {
        let _ = std::fs::remove_file(&temporary);
        return Err(write_error(path, &e));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_are_used_as_given() {
        let dir = std::env::temp_dir().join(format!("ti-kon-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("praxis.kon");
        std::fs::write(&file, "{}").unwrap();
        assert_eq!(resolve(file.to_str().unwrap()).unwrap(), file);
        assert_eq!(resolve(dir.join("praxis").to_str().unwrap()).unwrap(), file);
        assert!(matches!(
            resolve(dir.join("missing").to_str().unwrap()),
            Err(Error::ConnectorConfig(_))
        ));
        std::fs::remove_dir_all(dir).unwrap();
    }
}
