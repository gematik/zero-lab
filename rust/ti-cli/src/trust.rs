//! Trust material for commands: roots.json and the TSL, downloaded or cached, and
//! verified by ti-pki either way: the roots against the embedded anchor, the TSL against
//! the embedded TSL signer CA, its `NextUpdate`, the list seen before and, online, its
//! signer's OCSP status (`spec/tsl-xmldsig`). The embedded roots alone when offline with
//! nothing cached.

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
use ti_pki::ocsp::OcspChecker;
use ti_pki::revocation::RevocationChecker;
use ti_pki::tsl_signature::TslState;
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
    /// The TSL's `Id` and sequence number, to keep for the next run.
    tsl_state: Option<TslState>,
}

/// `--at`, or the system clock.
#[derive(Clone, Copy)]
struct At(Option<Timestamp>);

impl Clock for At {
    fn now(&self) -> Timestamp {
        self.0.unwrap_or_else(|| SystemClock.now())
    }
}

/// The `Id` and sequence number of the TSL last used from one URL, in the state
/// directory: `cache clear` leaves it, so an older list stays rejected (TSLSIG-053).
/// Losing it only weakens that check to what one run sees, so problems with the file
/// are warnings, never errors.
struct TslStateFile {
    path: PathBuf,
    verbose: u8,
}

impl TslStateFile {
    fn new(config: &TrustConfig, verbose: u8) -> Option<Self> {
        let key = Artifact::Tsl.cache_key(&config.tsl_url);
        let id = key.rsplit('/').next()?;
        match crate::paths::state_dir() {
            Ok(dir) => Some(TslStateFile {
                path: dir.join("tsl").join(format!("{id}.json")),
                verbose,
            }),
            Err(error) => {
                warning(format_args!(
                    "{error}: the TSL seen before is not kept, an older one is not rejected"
                ));
                None
            }
        }
    }

    /// The stored state; none before the first run.
    fn read(&self) -> Option<TslState> {
        let path = self.path.display();
        let bytes = match std::fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                self.verbose(format_args!("TSL state {path}: none yet"));
                return None;
            }
            Err(error) => {
                warning(format_args!("cannot read the TSL state {path}: {error}"));
                return None;
            }
        };
        match serde_json::from_slice::<TslState>(&bytes) {
            Ok(state) => {
                self.verbose(format_args!(
                    "TSL state {path}: #{} {}",
                    state.sequence_number, state.id
                ));
                Some(state)
            }
            Err(error) => {
                warning(format_args!(
                    "the TSL state {path} is unreadable ({error}); it is replaced"
                ));
                None
            }
        }
    }

    fn write(&self, state: &TslState) {
        let path = self.path.display();
        match self.store(state) {
            Ok(()) => self.verbose(format_args!(
                "TSL state {path}: kept #{} {}",
                state.sequence_number, state.id
            )),
            Err(error) => warning(format_args!(
                "cannot keep the TSL state in {path}: {error}; an older list is not rejected \
                 next time"
            )),
        }
    }

    fn store(&self, state: &TslState) -> std::io::Result<()> {
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_vec(state)?)?;
        std::fs::rename(&tmp, &self.path)
    }

    fn verbose(&self, message: impl std::fmt::Display) {
        if self.verbose >= 1 {
            crate::output::diagnostic(message);
        }
    }
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
    /// Warnings about the TSL: `no_ocsp_check` when its signer's status was not
    /// queried, `validity_warning_1` within the grace period.
    pub tsl_warnings: Vec<&'static str>,
    /// The TSL the CAs come from and what its trust rests on; absent with the embedded
    /// roots alone.
    pub tsl: Option<TslTrust>,
    /// Why the material is less than the environment's full set, if it is.
    pub note: Option<String>,
    /// Verified without brainpool (`--nist-only`): roots only, no TSL.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub nist_only: bool,
}

/// The verified TSL as a trust chain of its own: the list, its signer, the TSL signer CA.
#[derive(Serialize)]
pub struct TslTrust {
    /// `TSLSequenceNumber`.
    pub sequence_number: u64,
    /// The C.TSL.SIG certificate the list is signed with.
    pub signer: CertRef,
    /// `good` when the signer's OCSP status was queried, else absent.
    pub signer_ocsp: Option<&'static str>,
    /// The configured TSL signer CA that issued the signer.
    pub tsl_signer_ca: CertRef,
}

/// A certificate named in a report.
#[derive(Serialize)]
pub struct CertRef {
    pub common_name: String,
    pub not_after: String,
    #[serde(skip)]
    pub certificate: ti_pki::Certificate,
}

impl CertRef {
    fn new(certificate: &ti_pki::Certificate) -> Self {
        CertRef {
            common_name: certificate.subject_cn().to_owned(),
            not_after: certificate.not_after().to_string(),
            certificate: certificate.clone(),
        }
    }
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
    /// The `-v` count.
    verbose: u8,
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
            verbose: out.verbosity(),
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

    /// `config`'s trust material, verified at `at` or now: from the cache while fresh,
    /// else from the network (revalidating the cached copy). Offline, the cache or else
    /// the embedded roots. The TSL signer's OCSP status is queried online and at the
    /// current time only; it says nothing about another.
    pub fn load(
        &self,
        config: &TrustConfig,
        tier: Tier,
        at: Option<Timestamp>,
    ) -> Result<Material, CliError> {
        if !verifies_tsls(config) {
            return self.roots_only(config, at);
        }
        let clock = At(at);
        // The list seen before guards against an older one, but only for the current
        // time: a past instant may well need an older list.
        let state = at
            .is_none()
            .then(|| TslStateFile::new(config, self.verbose))
            .flatten();
        let stored = state.as_ref().and_then(TslStateFile::read);
        block_on(async {
            let material = if let Some(transport) = &self.transport {
                let reloader = reloader(
                    config,
                    tier,
                    self.loader(config, transport),
                    clock,
                    stored.clone(),
                )?;
                if at.is_none() {
                    let checker = OcspChecker::new(config, transport, SystemClock);
                    first_tick(&reloader.with_signer_status(checker)).await
                } else {
                    first_tick(&reloader).await
                }
                .map_err(CliError::from)
            } else {
                let reloader = reloader(
                    config,
                    tier,
                    self.loader(config, NoNetwork),
                    clock,
                    stored.clone(),
                )?;
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
            }?;
            if let (Some(file), Some(current)) = (&state, &material.tsl_state)
                && stored.as_ref() != Some(current)
            {
                file.write(current);
            }
            Ok(material)
        })
    }

    /// The roots alone, for algorithms that verify no TSL: roots.json from the cache or
    /// the network (else the embedded one), walked from the anchor at `at` or now.
    /// ti-pki fails a load whose TSL does not verify, rightly, since that may be
    /// tampering; here the TSL is left out by configuration, and the report says so.
    fn roots_only(
        &self,
        config: &TrustConfig,
        at: Option<Timestamp>,
    ) -> Result<Material, CliError> {
        let loaded = block_on(async {
            match &self.transport {
                Some(transport) => self.loader(config, transport).load(Artifact::Roots).await,
                None => self.loader(config, NoNetwork).load(Artifact::Roots).await,
            }
        });
        let (config, meta) = match loaded {
            Ok(loaded) => (
                TrustConfig {
                    roots: loaded.body.into(),
                    ..config.clone()
                },
                Some(loaded.meta),
            ),
            Err(LoadError::Offline(_)) => (config.clone(), None),
            Err(error) => return Err(CliError::TrustLoad(error.to_string())),
        };
        let store = roots::load(&config, at.unwrap_or_else(|| SystemClock.now()))
            .map_err(CliError::Trust)?
            .store();
        Ok(Material {
            info: TrustInfo {
                source: source_name(meta.as_ref().map(|m| m.source)),
                fetched_at: meta.as_ref().map(|m| m.fetched_at.to_string()),
                fetched_at_ts: meta.as_ref().map(|m| m.fetched_at),
                tsl_next_update: None,
                tsl_next_update_ts: None,
                roots: store.len(),
                intermediates: 0,
                tsl_warnings: Vec::new(),
                tsl: None,
                note: Some(
                    "without brainpool: roots up to the first brainpool signature, no TSL \
                     (its signer CAs are brainpool)"
                        .into(),
                ),
                nist_only: true,
            },
            tsl_state: None,
            store: Arc::new(store),
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
    clock: At,
    stored: Option<TslState>,
) -> Result<Reloader<L, At>, CliError>
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
    let reloader =
        Reloader::new(config.clone(), tier, loader, clock, policy).map_err(CliError::Trust)?;
    Ok(match stored {
        Some(state) => reloader.with_stored_tsl(state),
        None => reloader,
    })
}

async fn first_tick<L, R>(reloader: &Reloader<L, At, R>) -> Result<Material, Expired>
where
    L: Loader + Send + Sync,
    R: RevocationChecker + Send + Sync,
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
            tsl_warnings: status
                .tsl_warnings
                .iter()
                .filter(|w| w.code.is_warning())
                .map(|w| w.code.as_str())
                .collect(),
            tsl: match (&status.tsl_state, &status.tsl_signer) {
                (Some(state), Some((signer, ca))) => Some(TslTrust {
                    sequence_number: state.sequence_number,
                    signer: CertRef::new(signer),
                    signer_ocsp: status
                        .tsl_signer_status
                        .map(ti_pki::RevocationStatus::as_str),
                    tsl_signer_ca: CertRef::new(ca),
                }),
                _ => None,
            },
            note: None,
            nist_only: false,
        },
        tsl_state: status.tsl_state,
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
            tsl_warnings: Vec::new(),
            tsl: None,
            note: Some(note.to_owned()),
            nist_only: false,
        },
        tsl_state: None,
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

/// Whether `config`'s algorithms can check a TSL at all: every TSL is signed on
/// brainpoolP256r1 (TSLSIG-012), so without brainpool none verifies.
pub fn verifies_tsls(config: &TrustConfig) -> bool {
    ti_pki::algorithms::supports_key(
        &config.algorithms,
        ti_pki::algorithms::brainpool::BRAINPOOL_P256R1.as_ref(),
    )
}
