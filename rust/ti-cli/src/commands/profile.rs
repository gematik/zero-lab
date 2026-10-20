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
