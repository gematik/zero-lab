//! A dumb key/value store for loaded bodies. HTTP cache semantics (freshness,
//! revalidation, serving stale) live in [`CachingLoader`](super::CachingLoader), not
//! in the store, so a store is trivial to back with Redis, a file or a browser API.

use core::time::Duration;
use std::collections::HashMap;
use std::sync::Mutex;

use super::artifact::Meta;

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

impl<S: CacheStore + ?Sized> CacheStore for std::sync::Arc<S> {
    async fn get(&self, key: &str) -> Result<Option<CacheEntry>, CacheError> {
        (**self).get(key).await
    }

    async fn put(&self, key: &str, entry: &CacheEntry) -> Result<(), CacheError> {
        (**self).put(key, entry).await
    }
}

/// A cached body with its metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CacheEntry {
    /// The bytes.
    pub body: Vec<u8>,
    /// Their metadata; `fetched_at` is when the origin last produced or confirmed them.
    pub meta: Meta,
}

/// A cache store failure.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("cache store: {message}")]
pub struct CacheError {
    /// Human-readable detail.
    pub message: String,
}

/// How [`CachingLoader`](super::CachingLoader) uses its store.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CachePolicy {
    /// Serve from the cache without asking the origin while an entry is younger than this.
    pub max_age: Duration,
    /// When the origin fails, keep serving an entry for this long past `max_age`.
    pub stale_if_error: Duration,
    /// Never contact the origin; serve whatever the store holds. For air-gapped setups
    /// with a pre-populated store. The reloader's freshness policy still ages it out.
    pub offline: bool,
}

impl Default for CachePolicy {
    /// One hour fresh, a day of grace on origin errors, online.
    fn default() -> Self {
        CachePolicy {
            max_age: Duration::from_hours(1),
            stale_if_error: Duration::from_hours(24),
            offline: false,
        }
    }
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

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, HashMap<String, CacheEntry>>, CacheError> {
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
