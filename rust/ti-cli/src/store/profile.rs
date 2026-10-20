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

//! The profile in effect and its stores (spec/store section J): what the tool reads from
//! its options, environment and files before the store, which does no I/O of its own,
//! sees any of it.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use ti_store::store::profile::{self, Inputs, Platform, Profile};
use ti_store::store::registry::{self, Database, NamespaceSpec};
use ti_store::store::{
    KeyFileWrapper, Keyring, KeyringFile, OsRandom, Store, StoreError, parse_kek_file,
};
use ti_types::Timestamp;
use zeroize::Zeroizing;

use super::{AnyBackend, Db, Kind, Traced};
use crate::block::block_on;
use crate::cli::GlobalArgs;
use crate::error::{CliError, StoreFile};

/// A profile's store: its backend and, once the profile has a keyring, the keys that
/// seal its sealed namespaces.
pub type ProfileStore = Store<Traced<AnyBackend>, Keyring<OsRandom>>;

/// The profile in effect and the backend selected for it.
#[derive(Clone, Debug)]
pub struct Selected {
    /// The profile and its paths.
    pub profile: Profile,
    /// `TI_STORE_BACKEND`.
    pub kind: Kind,
}

impl Selected {
    /// STORE-091 to STORE-094 and STORE-131 from the command line and the environment;
    /// `--cache-dir` stands for `TI_CACHE_DIR`.
    ///
    /// # Errors
    ///
    /// `invalid_argument` for a profile name, directory or backend outside the rules.
    pub fn resolve(global: &GlobalArgs) -> Result<Self, CliError> {
        Self::resolve_named(global, global.profile.as_deref())
    }

    /// As [`resolve`](Self::resolve), with `name` in place of `--profile`.
    ///
    /// # Errors
    ///
    /// As [`resolve`](Self::resolve).
    pub fn resolve_named(global: &GlobalArgs, name: Option<&str>) -> Result<Self, CliError> {
        let cache_dir = global
            .cache_dir
            .as_deref()
            .map(|p| {
                p.to_str()
                    .map(str::to_owned)
                    .ok_or_else(|| CliError::Arguments("--cache-dir is not UTF-8".into()))
            })
            .transpose()?;
        let env = |key: &str| -> Option<String> {
            if key == "TI_CACHE_DIR" {
                return cache_dir.clone();
            }
            std::env::var(key).ok()
        };
        let home = std::env::home_dir().and_then(|h| h.to_str().map(str::to_owned));
        let platform = Platform::current();
        let active = profile::active_file(platform, &env, home.as_deref())
            .map(|path| match std::fs::read_to_string(&path) {
                Ok(text) => Ok(Some(text)),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(e) => Err(CliError::Read {
                    source_name: path,
                    source: e,
                }),
            })
            .transpose()?
            .flatten();
        let profile = profile::resolve(&Inputs {
            platform,
            flag: name,
            env: &env,
            active: active.as_deref(),
            home: home.as_deref(),
        })
        .map_err(|error| CliError::Store {
            profile: name.unwrap_or_default().to_owned(),
            file: StoreFile::Profile,
            path: String::new(),
            error,
        })?;
        let kind =
            Kind::from_env(std::env::var("TI_STORE_BACKEND").ok().as_deref()).map_err(|error| {
                CliError::Store {
                    profile: profile.name.clone(),
                    file: StoreFile::Profile,
                    path: "TI_STORE_BACKEND".into(),
                    error,
                }
            })?;
        Ok(Selected { profile, kind })
    }

    /// A store failure of this profile.
    pub fn fail(&self, file: StoreFile, path: &str, error: StoreError) -> CliError {
        CliError::Store {
            profile: self.profile.name.clone(),
            file,
            path: path.to_owned(),
            error,
        }
    }

    /// The path of the cache: `cache.db`, or the files tree.
    pub fn cache_path(&self) -> &str {
        match self.kind {
            Kind::Sqlite => &self.profile.cache_db,
            Kind::Files => &self.profile.cache_root,
        }
    }

    /// The path of the state: `state.db`, or the files tree.
    pub fn state_path(&self) -> &str {
        match self.kind {
            Kind::Sqlite => &self.profile.state_db,
            Kind::Files => &self.profile.state_root,
        }
    }

    /// The profile's cache. One that does not open is moved aside and created anew, with
    /// a warning: a cache may be lost at any time (STORE-108, STORE-128).
    ///
    /// # Errors
    ///
    /// A cache that cannot be created at all.
    pub fn open_cache(&self) -> Result<ProfileStore, CliError> {
        let path = self.cache_path().to_owned();
        let open = || {
            create_parent(Path::new(&path))?;
            AnyBackend::open(self.kind, Path::new(&path), Db::Cache)
        };
        let backend = match open() {
            Ok(b) => b,
            Err(error @ (StoreError::Malformed(_) | StoreError::UnsupportedVersion(_))) => {
                let aside = move_aside(Path::new(&path))
                    .map_err(|e| self.fail(StoreFile::CacheDb, &path, StoreError::Backend(e)))?;
                crate::output::warning(format_args!(
                    "profile {}: the cache {path} did not open ({}: {error}); moved to {} and \
                     created anew",
                    self.profile.name,
                    error.code(),
                    aside.display()
                ));
                open().map_err(|e| self.fail(StoreFile::CacheDb, &path, e))?
            }
            Err(error) => return Err(self.fail(StoreFile::CacheDb, &path, error)),
        };
        Store::new(
            Traced::from_env(backend),
            None,
            &namespaces(Database::Cache),
        )
        .map_err(|e| self.fail(StoreFile::CacheDb, &path, e))
    }

    /// The profile's state, with its keyring if it has one; without, its plain
    /// namespaces work and the sealed ones are refused with `no_keyring` (STORE-023). A
    /// state that does not open is never moved or recreated (STORE-128).
    ///
    /// # Errors
    ///
    /// A state, keyring or key file that does not open.
    pub fn open_state(&self) -> Result<ProfileStore, CliError> {
        let keyring = self.keyring()?;
        let path = self.state_path();
        create_parent(Path::new(path)).map_err(|e| self.fail(StoreFile::StateDb, path, e))?;
        let backend = AnyBackend::open(self.kind, Path::new(path), Db::State)
            .map_err(|e| self.fail(StoreFile::StateDb, path, e))?;
        Store::new(
            Traced::from_env(backend),
            keyring,
            &namespaces(Database::State),
        )
        .map_err(|e| self.fail(StoreFile::StateDb, path, e))
    }

    /// Creates `state.db` and `cache.db` (or their trees) if they do not exist.
    ///
    /// # Errors
    ///
    /// A database that does not open.
    pub fn create_databases(&self) -> Result<(), CliError> {
        for (path, db, file) in [
            (self.state_path(), Db::State, StoreFile::StateDb),
            (self.cache_path(), Db::Cache, StoreFile::CacheDb),
        ] {
            create_parent(Path::new(path))
                .and_then(|()| AnyBackend::open(self.kind, Path::new(path), db))
                .map_err(|e| self.fail(file, path, e))?;
        }
        Ok(())
    }

    /// Whether the profile has a keyring.
    pub fn has_keyring(&self) -> bool {
        Path::new(&self.profile.keyring).exists()
    }

    /// The keyring, unwrapped with the key file of STORE-094; none if the profile has
    /// none.
    fn keyring(&self) -> Result<Option<Keyring<OsRandom>>, CliError> {
        let path = &self.profile.keyring;
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(self.fail(StoreFile::Keyring, path, io(&e))),
        };
        let file =
            KeyringFile::parse(&bytes).map_err(|e| self.fail(StoreFile::Keyring, path, e))?;
        let wrapper = self.wrapper()?;
        block_on(Keyring::open(&file, &wrapper, OsRandom))
            .map(Some)
            .map_err(|e| self.fail(StoreFile::Keyring, path, e))
    }

    /// The `key-file` wrapper with the profile's key file.
    pub fn wrapper(&self) -> Result<KeyFileWrapper<OsRandom>, CliError> {
        let kek = read_kek(Path::new(&self.profile.kek_file))
            .map_err(|e| self.fail(StoreFile::KeyFile, &self.profile.kek_file, e))?;
        Ok(KeyFileWrapper::new(kek, OsRandom))
    }
}

/// The registered namespaces of one database.
fn namespaces(database: Database) -> Vec<NamespaceSpec> {
    registry::ALL
        .iter()
        .filter(|ns| ns.database == database)
        .copied()
        .collect()
}

/// Reads and checks a key file (STORE-094); a missing one is `no_keyring`'s cousin,
/// reported as `not_found`.
pub fn read_kek(path: &Path) -> Result<Zeroizing<[u8; 32]>, StoreError> {
    let content = Zeroizing::new(std::fs::read(path).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => StoreError::NotFound,
        _ => io(&e),
    })?);
    parse_kek_file(&content, mode(path))
}

#[cfg(unix)]
fn mode(path: &Path) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::metadata(path).ok().map(|m| m.permissions().mode())
}

#[cfg(not(unix))]
fn mode(_path: &Path) -> Option<u32> {
    None
}

/// Makes the directories above `path` with mode 0700.
pub fn create_parent(path: &Path) -> Result<(), StoreError> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder.create(parent).map_err(|e| io(&e))
}

/// Moves a broken cache to `<path>.broken-<time>`, with its WAL and shared-memory files,
/// and removes older such copies: at most the newest is kept (STORE-128).
fn move_aside(path: &Path) -> Result<PathBuf, String> {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("cache path has no file name")?;
    let prefix = format!("{name}.broken-");
    if let Some(dir) = path.parent()
        && let Ok(entries) = std::fs::read_dir(dir)
    {
        for entry in entries.flatten() {
            if entry.file_name().to_string_lossy().starts_with(&prefix) {
                let p = entry.path();
                let _ = std::fs::remove_dir_all(&p).or_else(|_| std::fs::remove_file(&p));
            }
        }
    }
    let aside = path.with_file_name(format!("{prefix}{}", now().0));
    std::fs::rename(path, &aside).map_err(|e| format!("{}: {e}", path.display()))?;
    for suffix in ["-wal", "-shm"] {
        let mut extra = path.as_os_str().to_owned();
        extra.push(suffix);
        let _ = std::fs::remove_file(PathBuf::from(extra));
    }
    Ok(aside)
}

/// The current time in whole seconds.
pub fn now() -> Timestamp {
    Timestamp(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()),
    )
}

fn io(e: &std::io::Error) -> StoreError {
    StoreError::Backend(e.to_string())
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::store::Kind;

    /// A profile in its own temporary directory, removed when dropped.
    pub struct TestProfile {
        pub dir: PathBuf,
        pub selected: Selected,
    }

    impl TestProfile {
        pub fn new(label: &str) -> Self {
            use std::sync::atomic::{AtomicUsize, Ordering};
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let dir = std::env::temp_dir().join(format!(
                "ti-profile-{label}-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            let env = |key: &str| match key {
                "TI_STATE_DIR" => Some(dir.join("state").display().to_string()),
                "TI_CACHE_DIR" => Some(dir.join("cache").display().to_string()),
                "TI_STORE_KEK_PATH" => Some(dir.join("store.kek").display().to_string()),
                _ => None,
            };
            let profile = profile::resolve(&Inputs {
                platform: Platform::current(),
                flag: Some("default"),
                env: &env,
                active: None,
                home: None,
            })
            .unwrap();
            TestProfile {
                dir: dir.clone(),
                selected: Selected {
                    profile,
                    kind: Kind::Sqlite,
                },
            }
        }
    }

    impl Drop for TestProfile {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    /// A test profile with a key file and a keyring, as `profile create` makes them.
    pub fn with_keyring(label: &str) -> TestProfile {
        use std::io::Write as _;
        let p = TestProfile::new(label);
        let kek = Zeroizing::new([7u8; 32]);
        let mut f = std::fs::File::create(&p.selected.profile.kek_file).unwrap();
        writeln!(
            f,
            "{}",
            <base64ct::Base64 as base64ct::Encoding>::encode_string(kek.as_slice())
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(
                &p.selected.profile.kek_file,
                std::fs::Permissions::from_mode(0o600),
            )
            .unwrap();
        }
        let wrapper = KeyFileWrapper::new(kek, OsRandom);
        let (_, file) = block_on(Keyring::create(&wrapper, OsRandom, now())).unwrap();
        create_parent(Path::new(&p.selected.profile.keyring)).unwrap();
        std::fs::write(&p.selected.profile.keyring, file.encode()).unwrap();
        p
    }
}
