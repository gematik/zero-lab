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

//! The download cache of ti-pki and ti-connector-client as plain files below the
//! profile's cache directory: one file per key, named by the hash of the key, so a key
//! made of a URL or a certificate id never shapes a path.

use std::fmt::Write as _;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use ti_store::{CacheEntry, CacheError, CacheStore, Meta, Source};
use ti_types::Timestamp;

use crate::cli::GlobalArgs;
use crate::error::CliError;
use crate::files::{create_private_dir, write_atomic};
use crate::profile::Profile;

const FORMAT_V1: u8 = 1;
/// Named after the format so that a new format gets its own directory and never reads
/// the entries of the old one.
const DIR: &str = "v1";

/// The longest lifetime any cache namespace had. Whether an entry is fresh is the
/// cache policy's question, answered from its metadata; this only bounds the disk.
const MAX_AGE: Duration = Duration::from_hours(30 * 24);

/// The profile's cache directory.
#[derive(Debug)]
pub struct FileCache {
    pub dir: PathBuf,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredMeta {
    etag: Option<String>,
    last_modified: Option<String>,
    fetched_at: u64,
    max_age_secs: Option<u64>,
}

fn error(message: String) -> CacheError {
    CacheError { message }
}

impl FileCache {
    /// The cache of `profile`, its directory created if missing.
    ///
    /// # Errors
    ///
    /// Any I/O error creating the directory.
    pub fn open(profile: &Profile) -> io::Result<Self> {
        let dir = profile.cache_dir.clone();
        create_private_dir(&dir.join(DIR))?;
        Ok(FileCache { dir })
    }
}

/// The cache of the profile in effect.
///
/// # Errors
///
/// A profile that does not resolve, or a cache directory that cannot be created.
pub fn open_cache(global: &GlobalArgs) -> Result<FileCache, CliError> {
    let profile = Profile::resolve(global)?;
    FileCache::open(&profile).map_err(|e| CliError::Cache {
        path: profile.cache_dir.display().to_string(),
        reason: e.to_string(),
    })
}

/// Where the entry of `key` lives: `<dir>/v1/<hex SHA-256 of key>`.
#[must_use]
pub fn entry_path(dir: &Path, key: &str) -> PathBuf {
    let hash = Sha256::digest(key.as_bytes())
        .iter()
        .fold(String::new(), |mut hex, b| {
            let _ = write!(hex, "{b:02x}");
            hex
        });
    dir.join(DIR).join(hash)
}

/// Removes every entry of the cache below `dir`.
///
/// # Errors
///
/// Any I/O error but the cache not existing.
pub fn clear(dir: &Path) -> io::Result<u64> {
    let root = dir.join(DIR);
    let entries = match fs::read_dir(&root) {
        Ok(entries) => entries
            .filter_map(Result::ok)
            .filter(|e| !e.file_name().to_string_lossy().starts_with('.'))
            .count(),
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(e),
    };
    match fs::remove_dir_all(&root) {
        Ok(()) => Ok(entries as u64),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(0),
        Err(e) => Err(e),
    }
}

/// The bytes of a cache file for `entry`: `u8 1 ‖ u32 length ‖ metadata as JSON ‖ body`.
///
/// # Errors
///
/// Metadata that does not serialize or is larger than a `u32` length.
pub fn encode(entry: &CacheEntry) -> Result<Vec<u8>, CacheError> {
    let meta = serde_json::to_vec(&StoredMeta {
        etag: entry.meta.etag.clone(),
        last_modified: entry.meta.last_modified.clone(),
        fetched_at: entry.meta.fetched_at.0,
        max_age_secs: entry.meta.max_age.map(|age| age.as_secs()),
    })
    .map_err(|e| error(e.to_string()))?;
    let len = u32::try_from(meta.len()).map_err(|_| error("cache metadata too large".into()))?;
    let mut out = Vec::with_capacity(5 + meta.len() + entry.body.len());
    out.push(FORMAT_V1);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&meta);
    out.extend_from_slice(&entry.body);
    Ok(out)
}

/// The entry, or none for bytes this version does not read: a cache file that cannot be
/// read is a miss.
#[must_use]
pub fn decode(payload: &[u8]) -> Option<CacheEntry> {
    let (&version, rest) = payload.split_first()?;
    if version != FORMAT_V1 || rest.len() < 4 {
        return None;
    }
    let (len, rest) = rest.split_at(4);
    let len = usize::try_from(u32::from_be_bytes(len.try_into().ok()?)).ok()?;
    if rest.len() < len {
        return None;
    }
    let (meta, body) = rest.split_at(len);
    let meta: StoredMeta = serde_json::from_slice(meta).ok()?;
    Some(CacheEntry {
        body: body.to_vec(),
        meta: Meta {
            etag: meta.etag,
            last_modified: meta.last_modified,
            fetched_at: Timestamp(meta.fetched_at),
            max_age: meta.max_age_secs.map(Duration::from_secs),
            source: Source::Cache,
        },
    })
}

/// Removes what has not been written for [`MAX_AGE`], leftover temporary files of a
/// crashed writer included. Reads never prune, so an offline run keeps what it has.
fn prune(root: &Path) -> io::Result<()> {
    let Some(oldest) = SystemTime::now().checked_sub(MAX_AGE) else {
        return Ok(());
    };
    for entry in fs::read_dir(root)?.filter_map(Result::ok) {
        let Ok(modified) = entry.metadata().and_then(|m| m.modified()) else {
            continue;
        };
        if modified < oldest {
            let _ = fs::remove_file(entry.path());
        }
    }
    Ok(())
}

impl CacheStore for FileCache {
    async fn get(&self, key: &str) -> Result<Option<CacheEntry>, CacheError> {
        match fs::read(entry_path(&self.dir, key)) {
            Ok(bytes) => Ok(decode(&bytes)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(error(format!("cache {}: {e}", self.dir.display()))),
        }
    }

    async fn put(&self, key: &str, entry: &CacheEntry) -> Result<(), CacheError> {
        let fail = |e: io::Error| error(format!("cache {}: {e}", self.dir.display()));
        let bytes = encode(entry)?;
        create_private_dir(&self.dir.join(DIR)).map_err(fail)?;
        write_atomic(&entry_path(&self.dir, key), &bytes).map_err(fail)?;
        // A failure to prune must not fail the download that was just stored.
        let _ = prune(&self.dir.join(DIR));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::block_on;
    use std::sync::Arc;

    const KEY: &str = "ti-pki/v1/tsl/0123456789abcdef";

    /// docs/design/testing.md: unknown fields are rejected where the format is ours.
    #[test]
    fn an_entry_with_an_unknown_metadata_field_is_no_entry() {
        let meta =
            br#"{"etag":null,"last_modified":null,"fetched_at":1,"max_age_secs":null,"extra":1}"#;
        let mut payload = vec![FORMAT_V1];
        payload.extend_from_slice(&u32::try_from(meta.len()).unwrap().to_be_bytes());
        payload.extend_from_slice(meta);
        payload.extend_from_slice(b"body");
        assert!(decode(&payload).is_none());
    }

    struct Dir(PathBuf);

    impl Dir {
        fn new(name: &str) -> Self {
            let dir = std::env::temp_dir().join(format!("ti-cache-{name}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&dir);
            Dir(dir)
        }

        fn cache(&self) -> FileCache {
            FileCache::open(&Profile {
                name: None,
                state_dir: self.0.join("state"),
                cache_dir: self.0.join("cache"),
            })
            .unwrap()
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn entry(body: &[u8]) -> CacheEntry {
        CacheEntry {
            body: body.to_vec(),
            meta: Meta {
                etag: Some("\"e\"".into()),
                last_modified: None,
                fetched_at: Timestamp(1_700_000_000),
                max_age: Some(Duration::from_secs(60)),
                source: Source::Http,
            },
        }
    }

    fn age(path: &Path, by: Duration) {
        fs::File::options()
            .write(true)
            .open(path)
            .unwrap()
            .set_modified(SystemTime::now() - by)
            .unwrap();
    }

    #[test]
    fn a_cache_entry_survives_a_new_process() {
        let dir = Dir::new("survives");
        block_on(dir.cache().put(KEY, &entry(b"<tsl/>"))).unwrap();
        let back = block_on(dir.cache().get(KEY)).unwrap().unwrap();
        assert_eq!(back.body, b"<tsl/>");
        assert_eq!(back.meta.etag.as_deref(), Some("\"e\""));
        assert_eq!(back.meta.fetched_at, Timestamp(1_700_000_000));
        assert_eq!(back.meta.max_age, Some(Duration::from_secs(60)));
        assert_eq!(back.meta.source, Source::Cache);
    }

    #[test]
    fn a_missing_entry_is_a_miss() {
        let dir = Dir::new("missing");
        assert!(block_on(dir.cache().get(KEY)).unwrap().is_none());
    }

    #[test]
    fn a_corrupt_entry_is_a_miss() {
        let dir = Dir::new("corrupt");
        let cache = dir.cache();
        block_on(cache.put(KEY, &entry(b"x"))).unwrap();
        let path = entry_path(&cache.dir, KEY);
        for bytes in [
            &b""[..],
            b"\x02rest",
            b"\x01\x00\x00\x00\x09{}",
            b"\x01\xff\xff\xff\xffab",
        ] {
            fs::write(&path, bytes).unwrap();
            assert!(block_on(cache.get(KEY)).unwrap().is_none(), "{bytes:?}");
        }
    }

    #[test]
    fn a_leftover_temp_file_is_not_an_entry() {
        let dir = Dir::new("leftover");
        let cache = dir.cache();
        let path = entry_path(&cache.dir, KEY);
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        fs::write(
            path.with_file_name(format!(".{name}.1.0.tmp")),
            encode(&entry(b"half")).unwrap(),
        )
        .unwrap();
        assert!(block_on(cache.get(KEY)).unwrap().is_none());
        assert_eq!(clear(&cache.dir).unwrap(), 0);
    }

    #[test]
    fn concurrent_writers_leave_a_whole_entry() {
        let dir = Dir::new("concurrent");
        let cache = Arc::new(dir.cache());
        let bodies: Vec<Vec<u8>> = (0..8u8).map(|i| vec![i; 64 * 1024]).collect();
        let threads: Vec<_> = bodies
            .iter()
            .cloned()
            .map(|body| {
                let cache = Arc::clone(&cache);
                std::thread::spawn(move || block_on(cache.put(KEY, &entry(&body))).unwrap())
            })
            .collect();
        for thread in threads {
            thread.join().unwrap();
        }
        let back = block_on(cache.get(KEY)).unwrap().unwrap();
        assert!(bodies.contains(&back.body));
    }

    #[test]
    fn a_key_with_slashes_stays_below_the_cache() {
        let dir = Dir::new("slashes");
        let cache = dir.cache();
        let key = "ti-pki/v1/ocsp/ab/cd";
        block_on(cache.put(key, &entry(b"ocsp"))).unwrap();
        let path = entry_path(&cache.dir, key);
        assert_eq!(path.parent().unwrap(), cache.dir.join("v1"));
        assert!(path.is_file());
        assert_eq!(block_on(cache.get(key)).unwrap().unwrap().body, b"ocsp");
    }

    #[test]
    fn a_put_removes_entries_older_than_thirty_days() {
        let dir = Dir::new("prune");
        let cache = dir.cache();
        block_on(cache.put("ti-pki/v1/roots/old", &entry(b"old"))).unwrap();
        block_on(cache.put("ti-pki/v1/roots/recent", &entry(b"recent"))).unwrap();
        let old = entry_path(&cache.dir, "ti-pki/v1/roots/old");
        age(&old, MAX_AGE + Duration::from_secs(60));
        age(
            &entry_path(&cache.dir, "ti-pki/v1/roots/recent"),
            MAX_AGE.checked_sub(Duration::from_hours(1)).unwrap(),
        );
        block_on(cache.put(KEY, &entry(b"new"))).unwrap();
        assert!(!old.exists());
        assert!(
            block_on(cache.get("ti-pki/v1/roots/recent"))
                .unwrap()
                .is_some()
        );
        assert!(block_on(cache.get(KEY)).unwrap().is_some());
    }

    #[test]
    fn a_get_keeps_old_entries() {
        let dir = Dir::new("keeps");
        let cache = dir.cache();
        block_on(cache.put(KEY, &entry(b"old"))).unwrap();
        age(&entry_path(&cache.dir, KEY), MAX_AGE * 2);
        assert!(block_on(cache.get(KEY)).unwrap().is_some());
        assert!(entry_path(&cache.dir, KEY).is_file());
    }

    #[test]
    fn clear_removes_the_entries_and_counts_them() {
        let dir = Dir::new("clear");
        let cache = dir.cache();
        assert_eq!(clear(&cache.dir).unwrap(), 0);
        block_on(cache.put(KEY, &entry(b"a"))).unwrap();
        block_on(cache.put("ti-pki/v1/ocsp/ab/cd", &entry(b"b"))).unwrap();
        assert_eq!(clear(&cache.dir).unwrap(), 2);
        assert!(block_on(cache.get(KEY)).unwrap().is_none());
        assert_eq!(clear(&cache.dir).unwrap(), 0);
        block_on(cache.put(KEY, &entry(b"c"))).unwrap();
        assert!(block_on(cache.get(KEY)).unwrap().is_some());
    }

    #[cfg(unix)]
    #[test]
    fn an_entry_file_is_private_to_the_user() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = Dir::new("mode");
        let cache = dir.cache();
        block_on(cache.put(KEY, &entry(b"a"))).unwrap();
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&entry_path(&cache.dir, KEY)), 0o600);
        assert_eq!(mode(&cache.dir.join("v1")), 0o700);
    }
}
