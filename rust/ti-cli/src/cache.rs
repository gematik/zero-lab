//! Downloaded trust material on disk, so a second run revalidates with an `ETag` instead
//! of downloading again and `--offline` has something to work with. The cache is as
//! untrusted as the network: everything read from it is verified again.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use ti_pki::Timestamp;
use ti_pki::load::{CacheEntry, CacheError, CacheStore, Meta, Source};

/// One body file and one metadata file per key, below `dir`.
pub struct FileCacheStore {
    dir: PathBuf,
}

/// [`Meta`] as stored; `source` is always rewritten to `cache` on the way out.
#[derive(Serialize, Deserialize)]
struct StoredMeta {
    etag: Option<String>,
    last_modified: Option<String>,
    fetched_at: u64,
    max_age_secs: Option<u64>,
}

impl FileCacheStore {
    /// A store in `dir`, created on the first write.
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        FileCacheStore { dir: dir.into() }
    }

    /// The files for `key`. Keys come from ti-pki (`ti-pki/v1/tsl/<hex>`); anything
    /// that could leave the directory is refused.
    fn paths(&self, key: &str) -> Result<(PathBuf, PathBuf), CacheError> {
        let safe = !key.is_empty()
            && key.split('/').all(|part| {
                !part.is_empty()
                    && part != "."
                    && part != ".."
                    && part
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
            });
        if !safe {
            return Err(error(format!("unusable cache key {key:?}")));
        }
        let base = self.dir.join(key);
        Ok((base.with_extension("body"), base.with_extension("json")))
    }
}

impl CacheStore for FileCacheStore {
    async fn get(&self, key: &str) -> Result<Option<CacheEntry>, CacheError> {
        let (body_path, meta_path) = self.paths(key)?;
        let (Some(body), Some(meta)) = (read(&body_path)?, read(&meta_path)?) else {
            return Ok(None);
        };
        // A damaged entry is a cache miss, not a failure: the network can replace it.
        let Ok(meta) = serde_json::from_slice::<StoredMeta>(&meta) else {
            return Ok(None);
        };
        Ok(Some(CacheEntry {
            body,
            meta: Meta {
                etag: meta.etag,
                last_modified: meta.last_modified,
                fetched_at: Timestamp(meta.fetched_at),
                max_age: meta.max_age_secs.map(Duration::from_secs),
                source: Source::Cache,
            },
        }))
    }

    async fn put(&self, key: &str, entry: &CacheEntry) -> Result<(), CacheError> {
        let (body_path, meta_path) = self.paths(key)?;
        let meta = StoredMeta {
            etag: entry.meta.etag.clone(),
            last_modified: entry.meta.last_modified.clone(),
            fetched_at: entry.meta.fetched_at.0,
            max_age_secs: entry.meta.max_age.map(|age| age.as_secs()),
        };
        let meta = serde_json::to_vec_pretty(&meta).map_err(|e| error(e.to_string()))?;
        // Body first: a reader finding new metadata always finds its body too.
        write_atomically(&body_path, &entry.body)?;
        write_atomically(&meta_path, &meta)
    }
}

fn read(path: &Path) -> Result<Option<Vec<u8>>, CacheError> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(error(format!("{}: {e}", path.display()))),
    }
}

/// Writes through a temporary file and a rename, so concurrent runs never read a
/// half-written file.
fn write_atomically(path: &Path, bytes: &[u8]) -> Result<(), CacheError> {
    let io = |e: std::io::Error| error(format!("{}: {e}", path.display()));
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(io)?;
    }
    let tmp = path.with_extension(format!("tmp{}", std::process::id()));
    std::fs::write(&tmp, bytes).map_err(io)?;
    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        io(e)
    })
}

fn error(message: String) -> CacheError {
    CacheError { message }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::block::block_on as run;

    #[test]
    fn round_trip_as_cache_source() {
        let dir = std::env::temp_dir().join(format!("ti-cache-{}", std::process::id()));
        let store = FileCacheStore::new(&dir);
        let key = "ti-pki/v1/tsl/0123456789abcdef";
        assert!(run(store.get(key)).unwrap().is_none());
        let entry = CacheEntry {
            body: b"<tsl/>".to_vec(),
            meta: Meta {
                etag: Some("\"v1\"".into()),
                last_modified: None,
                fetched_at: Timestamp(1_000),
                max_age: Some(Duration::from_secs(600)),
                source: Source::Http,
            },
        };
        run(store.put(key, &entry)).unwrap();
        let back = run(store.get(key)).unwrap().unwrap();
        assert_eq!(back.body, entry.body);
        assert_eq!(back.meta.etag, entry.meta.etag);
        assert_eq!(back.meta.fetched_at, Timestamp(1_000));
        assert_eq!(back.meta.max_age, Some(Duration::from_secs(600)));
        assert_eq!(back.meta.source, Source::Cache);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn keys_cannot_leave_the_directory() {
        let store = FileCacheStore::new("/nonexistent");
        for key in ["", "../x", "a//b", "/abs", "a/./b", "a b"] {
            assert!(store.paths(key).is_err(), "{key}");
        }
        assert!(store.paths("ti-pki/v1/roots/00ff").is_ok());
    }
}
