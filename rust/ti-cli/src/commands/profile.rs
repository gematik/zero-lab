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

//! `ti profile …` (spec/store section L): the profiles the TI tools share.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use base64ct::{Base64, Encoding as _};
use serde::Serialize;
use ti_store::store::{KeyFileWrapper, Keyring, OsRandom, Random as _, StoreError};
use zeroize::Zeroizing;

use crate::block::block_on;
use crate::cli::GlobalArgs;
use crate::error::{CliError, Exit, StoreFile};
use crate::output::{Document, Line, Output, SCHEMA, Tone};
use crate::store::now;
use crate::store::profile::{Selected, create_parent, read_kek};

/// STORE-132, where `profile create` mentions the key file.
const LOSS: &str = "losing the key file or the keyring loses the sealed records (tokens, TSL \
                    state, comfort IDs) and nothing else: log in again, and the TSL state is \
                    built again from a verified TSL";

#[derive(Serialize)]
struct CreateReport {
    schema: u32,
    profile: String,
    /// The key file the keyring is wrapped with.
    key_file: String,
    /// Whether this run made the key file.
    key_file_created: bool,
    keyring: String,
    state: String,
    cache: String,
    /// `TI_STORE_KEK_PATH` to set, when the key file is not where the tools look.
    kek_path_to_set: Option<String>,
}

/// `ti profile create [NAME] [--kek-file PATH]` (STORE-095, STORE-121).
pub fn create(
    global: &GlobalArgs,
    name: Option<&str>,
    kek_file: Option<&Path>,
    out: &Output,
) -> Result<Exit, CliError> {
    let selected = Selected::resolve_named(global, name.or(global.profile.as_deref()))?;
    let profile = &selected.profile;
    if selected.has_keyring() {
        return Err(CliError::Arguments(format!(
            "profile {} already has a keyring: {}; `ti profile delete {}` removes it",
            profile.name, profile.keyring, profile.name
        )));
    }
    let default_kek = PathBuf::from(&profile.kek_file);
    let (kek_path, kek, created) = match kek_file {
        Some(path) => {
            let kek = read_kek(path)
                .map_err(|e| selected.fail(StoreFile::KeyFile, &path.display().to_string(), e))?;
            (path.to_path_buf(), kek, false)
        }
        None => match read_kek(&default_kek) {
            Ok(kek) => (default_kek.clone(), kek, false),
            Err(StoreError::NotFound) => {
                let kek = new_kek_file(&default_kek)
                    .map_err(|e| selected.fail(StoreFile::KeyFile, &profile.kek_file, e))?;
                (default_kek.clone(), kek, true)
            }
            Err(e) => return Err(selected.fail(StoreFile::KeyFile, &profile.kek_file, e)),
        },
    };
    let wrapper = KeyFileWrapper::new(kek, OsRandom);
    let (_, file) = block_on(Keyring::create(&wrapper, OsRandom, now()))
        .map_err(|e| selected.fail(StoreFile::Keyring, &profile.keyring, e))?;
    write_private(Path::new(&profile.keyring), &file.encode())
        .map_err(|e| selected.fail(StoreFile::Keyring, &profile.keyring, e))?;
    selected.create_databases()?;

    let report = CreateReport {
        schema: SCHEMA,
        profile: profile.name.clone(),
        key_file: kek_path.display().to_string(),
        key_file_created: created,
        keyring: profile.keyring.clone(),
        state: selected.state_path().to_owned(),
        cache: selected.cache_path().to_owned(),
        kek_path_to_set: (kek_path != default_kek).then(|| kek_path.display().to_string()),
    };
    if out.is_json() {
        out.json(&report)?;
        return Ok(Exit::Ok);
    }
    let mut doc = Document::default();
    doc.section(format!("Profile {}", report.profile));
    doc.field(
        "key file",
        Line::code(&report.key_file).and_text(if created { " (new)" } else { "" }),
    );
    doc.field("keyring", Line::code(&report.keyring));
    doc.field("state", Line::code(&report.state));
    doc.field("cache", Line::code(&report.cache));
    if let Some(path) = &report.kek_path_to_set {
        doc.field(
            "next",
            Line::status(
                Tone::Warn,
                format!("set TI_STORE_KEK_PATH={path} for later runs"),
            ),
        );
    }
    doc.field("note", Line::dim(LOSS));
    out.render(&doc)?;
    Ok(Exit::Ok)
}

/// A new key-encryption key in a new file: 44 characters of base64 and a line feed, mode
/// 0600 (STORE-094, STORE-095).
fn new_kek_file(path: &Path) -> Result<Zeroizing<[u8; 32]>, StoreError> {
    let mut kek = Zeroizing::new([0u8; 32]);
    OsRandom.fill(kek.as_mut_slice())?;
    let mut text = Zeroizing::new(Base64::encode_string(kek.as_slice()));
    text.push('\n');
    create_parent(path)?;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut f = options.open(path).map_err(|e| io(path, &e))?;
    f.write_all(text.as_bytes())
        .and_then(|()| f.sync_all())
        .map_err(|e| io(path, &e))?;
    Ok(kek)
}

/// Writes `bytes` to a new temporary file with mode 0600 and renames it into place
/// (STORE-063).
fn write_private(path: &Path, bytes: &[u8]) -> Result<(), StoreError> {
    create_parent(path)?;
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    let written = (|| {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        let mut f = options.open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        std::fs::rename(&tmp, path)
    })();
    if let Err(e) = written {
        let _ = std::fs::remove_file(&tmp);
        return Err(io(path, &e));
    }
    #[cfg(unix)]
    if let Some(dir) = path.parent() {
        std::fs::File::open(dir)
            .and_then(|d| d.sync_all())
            .map_err(|e| io(dir, &e))?;
    }
    Ok(())
}

fn io(path: &Path, e: &std::io::Error) -> StoreError {
    StoreError::Backend(format!("{}: {e}", path.display()))
}

/// The profile named by the active file's first line, if any (STORE-091).
fn active_name(selected: &Selected) -> Option<String> {
    let path = selected.profile.active_file.as_ref()?;
    let text = std::fs::read_to_string(path).ok()?;
    let line = text.lines().next()?.trim_end_matches('\r');
    (!line.is_empty()).then(|| line.to_owned())
}

/// `<state>/profiles`, the directory every profile has a folder in.
fn profiles_dir(selected: &Selected) -> Option<PathBuf> {
    Path::new(&selected.profile.keyring)
        .parent()?
        .parent()
        .map(Path::to_path_buf)
}

/// The size of a database with its WAL, or of a files tree; none if absent.
fn size(path: &Path) -> Option<u64> {
    fn tree(path: &Path) -> u64 {
        std::fs::read_dir(path).map_or(0, |entries| {
            entries
                .flatten()
                .map(|e| match e.file_type() {
                    Ok(t) if t.is_dir() => tree(&e.path()),
                    Ok(t) if t.is_file() => e.metadata().map_or(0, |m| m.len()),
                    _ => 0,
                })
                .sum()
        })
    }
    let meta = std::fs::symlink_metadata(path).ok()?;
    if meta.is_dir() {
        return Some(tree(path));
    }
    let mut wal = path.as_os_str().to_owned();
    wal.push("-wal");
    Some(meta.len() + std::fs::metadata(PathBuf::from(wal)).map_or(0, |m| m.len()))
}

#[derive(Serialize)]
struct ListedProfile {
    name: String,
    active: bool,
    keyring: bool,
    key_file: bool,
    /// The state's format level, if it exists and opens.
    state_level: Option<u16>,
    state_bytes: Option<u64>,
    cache_bytes: Option<u64>,
}

#[derive(Serialize)]
struct ListReport {
    schema: u32,
    /// The profile in effect.
    current: String,
    profiles: Vec<ListedProfile>,
}

/// `ti profile list` (STORE-122).
pub fn list(global: &GlobalArgs, out: &Output) -> Result<Exit, CliError> {
    let current = Selected::resolve(global)?;
    let active = active_name(&current);
    let mut names: Vec<String> = profiles_dir(&current)
        .and_then(|dir| std::fs::read_dir(dir).ok())
        .map(|entries| {
            entries
                .flatten()
                .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
                .filter_map(|e| e.file_name().into_string().ok())
                .filter(|n| ti_store::store::profile::valid_name(n))
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    let mut profiles = Vec::new();
    for name in names {
        let s = Selected::resolve_named(global, Some(&name))?;
        let state = Path::new(s.state_path());
        let state_level = state
            .exists()
            .then(|| crate::store::AnyBackend::open(s.kind, state, crate::store::Db::State).ok())
            .flatten()
            .and_then(|b| b.inspect().ok())
            .map(|i| i.level);
        profiles.push(ListedProfile {
            active: active.as_deref() == Some(name.as_str()),
            keyring: s.has_keyring(),
            key_file: Path::new(&s.profile.kek_file).exists(),
            state_level,
            state_bytes: size(state),
            cache_bytes: size(Path::new(s.cache_path())),
            name,
        });
    }
    let report = ListReport {
        schema: SCHEMA,
        current: current.profile.name.clone(),
        profiles,
    };
    if out.is_json() {
        out.json(&report)?;
        return Ok(Exit::Ok);
    }
    let mut doc = Document::default();
    doc.section("Profiles");
    let kib = |b: Option<u64>| {
        b.map_or(Line::dim("-"), |b| {
            Line::text(format!("{} KiB", b.div_ceil(1024)))
        })
    };
    let yes = |v: bool| {
        if v {
            Line::text("yes")
        } else {
            Line::dim("no")
        }
    };
    doc.table(
        &[
            "profile", "active", "keyring", "key file", "level", "state", "cache",
        ],
        report
            .profiles
            .iter()
            .map(|p| {
                let name = if p.name == report.current {
                    Line::strong(&p.name)
                } else {
                    Line::text(&p.name)
                };
                vec![
                    name,
                    yes(p.active),
                    yes(p.keyring),
                    yes(p.key_file),
                    p.state_level
                        .map_or(Line::dim("-"), |l| Line::text(l.to_string())),
                    kib(p.state_bytes),
                    kib(p.cache_bytes),
                ]
            })
            .collect(),
    );
    if report.profiles.is_empty() {
        doc.paragraph(Line::dim("no profile yet: `ti profile create`"));
    }
    out.render(&doc)?;
    Ok(Exit::Ok)
}

#[derive(Serialize)]
struct UseReport {
    schema: u32,
    profile: String,
    active_file: String,
}

/// `ti profile use NAME`: writes the active file (STORE-091, STORE-122).
pub fn use_profile(global: &GlobalArgs, name: &str, out: &Output) -> Result<Exit, CliError> {
    let selected = Selected::resolve_named(global, Some(name))?;
    let Some(active) = selected.profile.active_file.clone() else {
        return Err(CliError::Arguments(
            "no configuration directory for the active file: set XDG_CONFIG_HOME or use --profile"
                .into(),
        ));
    };
    write_private(Path::new(&active), format!("{name}\n").as_bytes())
        .map_err(|e| selected.fail(StoreFile::Profile, &active, e))?;
    let report = UseReport {
        schema: SCHEMA,
        profile: selected.profile.name.clone(),
        active_file: active,
    };
    if out.is_json() {
        out.json(&report)?;
    } else {
        let mut doc = Document::default();
        doc.field("active profile", Line::strong(&report.profile));
        doc.field("written to", Line::code(&report.active_file));
        if std::env::var("TI_PROFILE").is_ok_and(|v| !v.is_empty()) {
            doc.field(
                "note",
                Line::status(Tone::Warn, "TI_PROFILE is set and takes precedence"),
            );
        }
        out.render(&doc)?;
    }
    Ok(Exit::Ok)
}

#[derive(Serialize)]
struct DeleteReport {
    schema: u32,
    profile: String,
    /// What was removed, keyring first.
    removed: Vec<String>,
}

/// `ti profile delete NAME --yes` (STORE-096, STORE-122): the keyring first, so that
/// whatever is left of the records can no longer be opened; then the state and cache,
/// the default key file, and the active file if it names this profile.
pub fn delete(global: &GlobalArgs, name: &str, yes: bool, out: &Output) -> Result<Exit, CliError> {
    let selected = Selected::resolve_named(global, Some(name))?;
    let profile = &selected.profile;
    if !yes {
        return Err(CliError::Arguments(format!(
            "deleting profile {name} removes its keyring, state and cache, and with them its \
             tokens, TSL state and comfort IDs: pass --yes"
        )));
    }
    let fail = |path: &Path, e: &std::io::Error| {
        selected.fail(
            StoreFile::Keyring,
            &path.display().to_string(),
            StoreError::Backend(e.to_string()),
        )
    };
    let mut removed = Vec::new();
    let keyring = Path::new(&profile.keyring);
    match std::fs::remove_file(keyring) {
        Ok(()) => {
            removed.push(profile.keyring.clone());
            #[cfg(unix)]
            if let Some(dir) = keyring.parent() {
                std::fs::File::open(dir)
                    .and_then(|d| d.sync_all())
                    .map_err(|e| fail(dir, &e))?;
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(fail(keyring, &e)),
    }
    // the profile's own folders: <state>/profiles/NAME and <cache>/profiles/NAME
    for dir in [
        keyring.parent().map(Path::to_path_buf),
        Path::new(&profile.cache_db).parent().map(Path::to_path_buf),
    ]
    .into_iter()
    .flatten()
    {
        match std::fs::remove_dir_all(&dir) {
            Ok(()) => removed.push(dir.display().to_string()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(fail(&dir, &e)),
        }
    }
    // only the default key file: one named by TI_STORE_KEK_PATH is the user's
    if std::env::var_os("TI_STORE_KEK_PATH").is_none() {
        let kek = Path::new(&profile.kek_file);
        if std::fs::remove_file(kek).is_ok() {
            removed.push(profile.kek_file.clone());
            if let Some(dir) = kek.parent() {
                let _ = std::fs::remove_dir(dir);
            }
        }
    }
    if active_name(&selected).as_deref() == Some(name)
        && let Some(active) = &profile.active_file
        && std::fs::remove_file(active).is_ok()
    {
        removed.push(active.clone());
    }
    let report = DeleteReport {
        schema: SCHEMA,
        profile: profile.name.clone(),
        removed,
    };
    if out.is_json() {
        out.json(&report)?;
    } else {
        let mut doc = Document::default();
        doc.section(format!("Profile {} deleted", report.profile));
        if report.removed.is_empty() {
            doc.paragraph(Line::dim("nothing to remove"));
        }
        for path in &report.removed {
            doc.field("removed", Line::code(path));
        }
        out.render(&doc)?;
    }
    Ok(Exit::Ok)
}

#[derive(Serialize)]
struct ShowReport {
    schema: u32,
    profile: String,
    from: &'static str,
    backend: &'static str,
    active_file: Option<String>,
    key_file: String,
    key_file_found: bool,
    keyring: String,
    keyring_found: bool,
    state: String,
    cache: String,
}

/// `ti profile show`: the profile in effect, where its name came from, and its paths.
pub fn show(global: &GlobalArgs, out: &Output) -> Result<Exit, CliError> {
    let selected = Selected::resolve(global)?;
    let p = &selected.profile;
    let report = ShowReport {
        schema: SCHEMA,
        profile: p.name.clone(),
        from: p.from.as_str(),
        backend: match selected.kind {
            crate::store::Kind::Sqlite => "sqlite",
            crate::store::Kind::Files => "files",
        },
        active_file: p.active_file.clone(),
        key_file: p.kek_file.clone(),
        key_file_found: Path::new(&p.kek_file).exists(),
        keyring: p.keyring.clone(),
        keyring_found: selected.has_keyring(),
        state: selected.state_path().to_owned(),
        cache: selected.cache_path().to_owned(),
    };
    if out.is_json() {
        out.json(&report)?;
        return Ok(Exit::Ok);
    }
    let found = |path: &str, found: bool| {
        let line = Line::code(path);
        if found {
            line
        } else {
            line.and_dim(" (not found)")
        }
    };
    let mut doc = Document::default();
    doc.section(format!("Profile {}", report.profile));
    doc.field("from", Line::text(report.from));
    doc.field("backend", Line::text(report.backend));
    doc.field("key file", found(&report.key_file, report.key_file_found));
    doc.field("keyring", found(&report.keyring, report.keyring_found));
    doc.field("state", Line::code(&report.state));
    doc.field("cache", Line::code(&report.cache));
    if let Some(active) = &report.active_file {
        doc.field("active file", Line::code(active));
    }
    if !report.keyring_found {
        doc.field(
            "next",
            Line::status(Tone::Warn, "no keyring: `ti profile create`"),
        );
    }
    out.render(&doc)?;
    Ok(Exit::Ok)
}
