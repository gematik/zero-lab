//! A dumb key/value store for bodies and their metadata. HTTP cache semantics
//! (freshness, revalidation, serving stale) live in [`Cache`](crate::Cache), not in the
//! store, so a store is trivial to back with Redis, a file or a browser API.

use core::time::Duration;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};

use ti_types::Timestamp;

/// Persists cache entries by key.
#[allow(
    async_fn_in_trait,
    reason = "no Send bound on purpose: implementable on wasm32"
)]
pub trait CacheStore {
    /// The entry stored under `key`, if any.
    async fn get(&self, key: &str) -> Result<Option<CacheEntry>, CacheError>;
    /// Stores `entry` under `key`, replacing what was there.
    async fn put(&self, key: &str, entry: &CacheEntry) -> Result<(), CacheError>;
}

impl<S: CacheStore + ?Sized> CacheStore for &S {
    async fn get(&self, key: &str) -> Result<Option<CacheEntry>, CacheError> {
        (**self).get(key).await
    }

    async fn put(&self, key: &str, entry: &CacheEntry) -> Result<(), CacheError> {
        (**self).put(key, entry).await
    }
}

impl<S: CacheStore + ?Sized> CacheStore for Arc<S> {
    async fn get(&self, key: &str) -> Result<Option<CacheEntry>, CacheError> {
        (**self).get(key).await
    }

    async fn put(&self, key: &str, entry: &CacheEntry) -> Result<(), CacheError> {
        (**self).put(key, entry).await
    }
}

/// A body with its metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CacheEntry {
    /// The bytes.
    pub body: Vec<u8>,
    /// Their metadata; `fetched_at` is when the origin last produced or confirmed them.
    pub meta: Meta,
}

/// Metadata of a body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Meta {
    /// HTTP `ETag`, or `sha256:<hex>` of the body for sources without HTTP validators.
    pub etag: Option<String>,
    /// HTTP `Last-Modified`, verbatim.
    pub last_modified: Option<String>,
    /// When the body was obtained from its origin; revalidation moves it forward.
    pub fetched_at: Timestamp,
    /// `Cache-Control: max-age` of the response, if any.
    pub max_age: Option<Duration>,
    /// Where the body came from.
    pub source: Source,
}

impl Meta {
    /// Metadata without validators or `max-age`.
    pub fn new(fetched_at: Timestamp, source: Source) -> Self {
        Meta {
            etag: None,
            last_modified: None,
            fetched_at,
            max_age: None,
            source,
        }
    }
}

/// Where a body came from. Informational only: trust never depends on it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Source {
    /// Fetched over HTTP.
    Http,
    /// Read from a file.
    File,
    /// Taken from an offline bundle.
    Bundle,
    /// Served by a cache store.
    Cache,
    /// Compiled into the binary.
    Embedded,
}

/// A cache store failure.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("cache store: {message}")]
pub struct CacheError {
    /// Human-readable detail.
    pub message: String,
}

/// An in-process [`CacheStore`].
#[derive(Debug, Default)]
pub struct MemoryCacheStore {
    entries: Mutex<HashMap<String, CacheEntry>>,
}

impl MemoryCacheStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> Result<MutexGuard<'_, HashMap<String, CacheEntry>>, CacheError> {
        self.entries.lock().map_err(|_| CacheError {
            message: "memory store lock poisoned".into(),
        })
    }
}

impl CacheStore for MemoryCacheStore {
    async fn get(&self, key: &str) -> Result<Option<CacheEntry>, CacheError> {
        Ok(self.lock()?.get(key).cloned())
    }

    async fn put(&self, key: &str, entry: &CacheEntry) -> Result<(), CacheError> {
        self.lock()?.insert(key.to_owned(), entry.clone());
        Ok(())
    }
}
