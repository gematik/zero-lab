//! Trust material for validation: roots.json and the TSL, downloaded or cached, and
//! verified by ti-pki against the embedded anchor either way; the embedded roots alone
//! when offline with nothing cached.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;
use ti_pki::load::{
    ArtifactRequest, ArtifactResponse, CacheEntry, CacheError, CachePolicy, CacheStore,
    CachingLoader, HttpLoader, LoadError, MemoryCacheStore, PostRequest, ReloadError,
    ReloadOutcome, ReloadPolicy, Reloader, Source, SystemClock, Transport, TransportError,
    TransportErrorKind,
};
use ti_pki::{Clock, Tier, Timestamp, TrustConfig, TrustStore, roots};

use crate::error::CliError;

/// How long downloaded material may be used without the network. Production keeps
/// ti-pki's maximum; elsewhere a week, so `--offline` stays useful on a laptop.
const NONPROD_HARD_EXPIRY: Duration = Duration::from_hours(7 * 24);

/// The store validation runs against, and where it came from.
pub struct Material {
    /// The verified roots and the TSL CAs they signed.
    pub store: Arc<TrustStore>,
    /// For the report.
    pub info: TrustInfo,
}

/// Where the trust material came from, for the report.
#[derive(Serialize)]
pub struct TrustInfo {
    /// `http`, `cache` or `embedded`.
    pub source: &'static str,
    /// When the material was downloaded or last confirmed; absent when embedded.
    pub fetched_at: Option<String>,
    #[serde(skip)]
    pub fetched_at_ts: Option<Timestamp>,
    /// The TSL's `NextUpdate`.
    pub tsl_next_update: Option<String>,
    #[serde(skip)]
    pub tsl_next_update_ts: Option<Timestamp>,
    /// Trusted roots.
    pub roots: usize,
    /// TSL CAs a root signed.
    pub intermediates: usize,
    /// Why the material is less than the environment's full set, if it is.
    pub note: Option<String>,
}

/// Loads `config`'s trust material: from the cache while fresh, else from the network
/// (revalidating the cached copy), never from the network when `offline`.
pub async fn load<T>(
    config: &TrustConfig,
    tier: Tier,
    transport: T,
    cache_dir: Option<PathBuf>,
    offline: bool,
) -> Result<Material, CliError>
where
    T: Transport + Send + Sync,
{
    let store = match cache_dir {
        Some(dir) => Store::File(crate::cache::FileCacheStore::new(dir)),
        None => Store::Memory(MemoryCacheStore::new()),
    };
    let loader = CachingLoader::new(
        HttpLoader::new(config, transport, SystemClock),
        store,
        SystemClock,
        CachePolicy {
            offline,
            ..CachePolicy::default()
        },
    );
    let hard_expiry = match tier {
        Tier::Prod => ReloadPolicy::default().hard_expiry,
        Tier::NonProd => NONPROD_HARD_EXPIRY,
    };
    let policy = ReloadPolicy {
        hard_expiry,
        ..ReloadPolicy::default()
    };
    let reloader = Reloader::new(config.clone(), tier, loader, SystemClock, policy)
        .map_err(CliError::Trust)?;

    // The first tick either swaps in material or expires; any other outcome (one added
    // to ti-pki later) is read through the snapshot below.
    if let ReloadOutcome::Expired { error } = reloader.tick().await {
        return match error {
            ReloadError::Load(LoadError::Offline(_)) if offline => embedded(
                config,
                "offline and nothing cached: embedded roots only, no TSL",
            ),
            ReloadError::TooOld { age } if offline => embedded(
                config,
                &format!(
                    "cached material is {} old: embedded roots only, no TSL",
                    crate::output::document::span(age.as_secs())
                ),
            ),
            ReloadError::Verify(error) => Err(CliError::TrustLoad(format!(
                "downloaded material failed verification: {error}"
            ))),
            error => Err(CliError::TrustLoad(error.to_string())),
        };
    }
    let store = reloader
        .handle()
        .snapshot()
        .map_err(|e| CliError::TrustLoad(e.to_string()))?;
    let status = reloader.handle().status();
    Ok(Material {
        info: TrustInfo {
            source: source_name(status.source),
            fetched_at: status.fetched_at.map(|t| t.to_string()),
            fetched_at_ts: status.fetched_at,
            tsl_next_update: status.tsl_next_update.map(|t| t.to_string()),
            tsl_next_update_ts: status.tsl_next_update,
            roots: store.len(),
            intermediates: store.intermediates().len(),
            note: None,
        },
        store,
    })
}

fn embedded(config: &TrustConfig, note: &str) -> Result<Material, CliError> {
    let store = roots::load(config, SystemClock.now())
        .map_err(CliError::Trust)?
        .store();
    Ok(Material {
        info: TrustInfo {
            source: "embedded",
            fetched_at: None,
            fetched_at_ts: None,
            tsl_next_update: None,
            tsl_next_update_ts: None,
            roots: store.len(),
            intermediates: 0,
            note: Some(note.to_owned()),
        },
        store: Arc::new(store),
    })
}

fn source_name(source: Option<Source>) -> &'static str {
    match source {
        Some(Source::Http) => "http",
        Some(Source::Cache) => "cache",
        Some(Source::File) => "file",
        Some(Source::Bundle) => "bundle",
        _ => "embedded",
    }
}

/// The cache on disk, or in memory when no cache directory can be derived.
enum Store {
    File(crate::cache::FileCacheStore),
    Memory(MemoryCacheStore),
}

impl CacheStore for Store {
    async fn get(&self, key: &str) -> Result<Option<CacheEntry>, CacheError> {
        match self {
            Store::File(store) => store.get(key).await,
            Store::Memory(store) => store.get(key).await,
        }
    }

    async fn put(&self, key: &str, entry: &CacheEntry) -> Result<(), CacheError> {
        match self {
            Store::File(store) => store.put(key, entry).await,
            Store::Memory(store) => store.put(key, entry).await,
        }
    }
}

/// The transport of `--offline`: every request fails, so nothing leaves the machine
/// even where a component would otherwise ask the network.
pub struct NoNetwork;

impl Transport for NoNetwork {
    async fn get(&self, req: &ArtifactRequest<'_>) -> Result<ArtifactResponse, TransportError> {
        Err(refused(req.url))
    }

    async fn post(&self, req: &PostRequest<'_>) -> Result<Vec<u8>, TransportError> {
        Err(refused(req.url))
    }
}

fn refused(url: &str) -> TransportError {
    TransportError {
        kind: TransportErrorKind::Other,
        message: format!("offline: not requesting {url}"),
        retryable: false,
    }
}
