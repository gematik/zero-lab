//! Trust material for commands: roots.json and the TSL, downloaded or cached, and
//! verified by ti-pki against the embedded anchor either way; the embedded roots alone
//! when offline with nothing cached.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;
use ti_pki::load::{
    Artifact, ArtifactRequest, ArtifactResponse, CacheEntry, CacheError, CachePolicy, CacheStore,
    CachingLoader, HttpLoader, LoadError, Loader, MemoryCacheStore, Meta, PostRequest, ReloadError,
    ReloadOutcome, ReloadPolicy, Reloader, Source, SystemClock, Transport, TransportError,
    TransportErrorKind,
};
use ti_pki::{Clock, Tier, Timestamp, TrustConfig, TrustStore, roots};

use crate::block::block_on;
use crate::cli::GlobalArgs;
use crate::error::CliError;
use crate::http::{self, Http};
use crate::output::{Output, warning};
use crate::paths;

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

/// How a command reaches trust material: over the network or not, and where the cache
/// is. One per invocation, so every load shares the cache and the transport.
pub struct Session {
    transport: Option<Http>,
    cache_dir: Option<PathBuf>,
    /// Stands in for the cache directory when none can be derived.
    memory: Arc<MemoryCacheStore>,
    /// `-k` is in effect for downloads.
    pub insecure: bool,
}

impl Session {
    /// A session for `global`'s cache and HTTP options; with `offline`, no request is
    /// ever made. Warns on stderr when `-k` is in effect.
    pub fn new(global: &GlobalArgs, offline: bool, out: &Output) -> Result<Self, CliError> {
        let cache_dir = match paths::cache_dir(global.cache_dir.as_deref()) {
            Ok(dir) => Some(dir),
            Err(error) => {
                out.verbose(1, format_args!("{error}; caching in memory only"));
                None
            }
        };
        let insecure = global.net.insecure && !offline;
        if insecure {
            warning("-k: TLS certificates of downloads are not checked");
        }
        let transport = if offline {
            None
        } else {
            Some(http::transport(&global.net, out.verbosity())?)
        };
        Ok(Session {
            transport,
            cache_dir,
            memory: Arc::default(),
            insecure,
        })
    }

    /// The transport for OCSP; `None` offline.
    pub fn transport(&self) -> Option<&Http> {
        self.transport.as_ref()
    }

    /// Whether requests are made.
    pub fn is_offline(&self) -> bool {
        self.transport.is_none()
    }

    /// `config`'s trust material, verified: from the cache while fresh, else from the
    /// network (revalidating the cached copy). Offline, the cache or else the embedded
    /// roots.
    pub fn load(&self, config: &TrustConfig, tier: Tier) -> Result<Material, CliError> {
        block_on(async {
            if let Some(transport) = &self.transport {
                let reloader = reloader(config, tier, self.loader(config, transport))?;
                first_tick(&reloader).await.map_err(CliError::from)
            } else {
                let reloader = reloader(config, tier, self.loader(config, NoNetwork))?;
                match first_tick(&reloader).await {
                    Err(Expired(ReloadError::Load(LoadError::Offline(_)))) => embedded(
                        config,
                        "offline and nothing cached: embedded roots only, no TSL",
                    ),
                    Err(Expired(ReloadError::TooOld { age })) => embedded(
                        config,
                        &format!(
                            "cached material is {} old: embedded roots only, no TSL",
                            crate::output::document::span(age.as_secs())
                        ),
                    ),
                    other => other.map_err(CliError::from),
                }
            }
        })
    }

    /// The TSL as loaded (unverified bytes; see [`ti_pki::tsl`]), with where it came
    /// from. Call after [`load`](Self::load), which has refreshed the cache.
    pub fn tsl(&self, config: &TrustConfig) -> Result<(Vec<u8>, Meta), CliError> {
        let loaded = block_on(async {
            match &self.transport {
                Some(transport) => self.loader(config, transport).load(Artifact::Tsl).await,
                None => self.loader(config, NoNetwork).load(Artifact::Tsl).await,
            }
        });
        match loaded {
            Ok(loaded) => Ok((loaded.body, loaded.meta)),
            Err(LoadError::Offline(_)) => Err(CliError::TrustLoad(
                "offline and no TSL cached; run once without --offline".into(),
            )),
            Err(error) => Err(CliError::TrustLoad(error.to_string())),
        }
    }

    fn loader<T: Transport + Send + Sync>(
        &self,
        config: &TrustConfig,
        transport: T,
    ) -> CachingLoader<HttpLoader<T, SystemClock>, Store, SystemClock> {
        let store = match &self.cache_dir {
            Some(dir) => Store::File(crate::cache::FileCacheStore::new(dir)),
            None => Store::Memory(Arc::clone(&self.memory)),
        };
        CachingLoader::new(
            HttpLoader::new(config, transport, SystemClock),
            store,
            SystemClock,
            CachePolicy {
                offline: self.is_offline(),
                ..CachePolicy::default()
            },
        )
    }
}

/// A first tick that left no material, with why.
struct Expired(ReloadError);

impl From<Expired> for CliError {
    fn from(Expired(error): Expired) -> Self {
        match error {
            ReloadError::Verify(error) => {
                CliError::TrustLoad(format!("downloaded material failed verification: {error}"))
            }
            error => CliError::TrustLoad(error.to_string()),
        }
    }
}

fn reloader<L>(
    config: &TrustConfig,
    tier: Tier,
    loader: L,
) -> Result<Reloader<L, SystemClock>, CliError>
where
    L: Loader + Send + Sync,
{
    let hard_expiry = match tier {
        Tier::Prod => ReloadPolicy::default().hard_expiry,
        Tier::NonProd => NONPROD_HARD_EXPIRY,
    };
    let policy = ReloadPolicy {
        hard_expiry,
        ..ReloadPolicy::default()
    };
    Reloader::new(config.clone(), tier, loader, SystemClock, policy).map_err(CliError::Trust)
}

async fn first_tick<L>(reloader: &Reloader<L, SystemClock>) -> Result<Material, Expired>
where
    L: Loader + Send + Sync,
{
    // The first tick either swaps in material or expires; any other outcome (one added
    // to ti-pki later) is read through the snapshot below.
    if let ReloadOutcome::Expired { error } = reloader.tick().await {
        return Err(Expired(error));
    }
    let store = reloader
        .handle()
        .snapshot()
        .map_err(|_| Expired(ReloadError::Load(LoadError::Unavailable(Artifact::Roots))))?;
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
    Memory(Arc<MemoryCacheStore>),
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
struct NoNetwork;

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
