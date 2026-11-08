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

//! Trust material for the operations: roots.json and the TSL, downloaded or cached, and
//! verified by ti-pki either way: the roots against the embedded anchor, the TSL against
//! the embedded TSL signer CA, its `NextUpdate`, the list seen before and, online, its
//! signer's OCSP status (`spec/tsl-xmldsig`). The embedded roots alone when offline with
//! nothing cached.

#[cfg(test)]
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use core::fmt;

use serde::Serialize;
use ti_pki::load::{
    Artifact, ArtifactRequest, ArtifactResponse, AtTime, CacheEntry, CacheError, CachePolicy,
    CacheStore, CachingLoader, HttpLoader, LoadError, Loader, MemoryCacheStore, NoNetwork,
    PostRequest, ReadBackError, ReloadError, ReloadOutcome, ReloadPolicy, Reloader, Source,
    Transport, TransportError, TrustMaterial, read_back, verify_read_back,
};
use ti_pki::ocsp::OcspChecker;
use ti_pki::revocation::RevocationChecker;
use ti_pki::tsl_signature::{TslCode, TslState, VerifiedTsl};
use ti_pki::{Env, Tier, Timestamp, TrustConfig, TrustStore, roots};

use crate::block_on;
use crate::client::Client;
use crate::error::Error;
use crate::file_cache::FileCache;
use crate::files::{Dirs, create_private_dir, path_component, write_atomic};
use crate::http::{Http, Observer};

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

/// The system clock as a type the loaders below can name.
type Now = fn() -> Timestamp;

/// `--at`, or the system clock.
fn at_or_now(at: Option<Timestamp>) -> impl Fn() -> Timestamp + Copy + Send + Sync {
    move || at.unwrap_or_else(Timestamp::now)
}

/// The `Id` and sequence number of the TSL last used from one URL, kept as a plain file
/// in the profile's state directory: clearing the cache leaves it, so an older list stays
/// rejected (TSLSIG-053). It needs no setup, and it is never dropped silently: a file
/// that cannot be read, parsed or written is an error, since a rollback check that
/// quietly stopped working would be worse than a command that stops.
struct TslStateStore {
    path: PathBuf,
    observer: Option<Observer>,
}

impl TslStateStore {
    /// The state of `config`'s TSL, keyed as its cache entry is.
    fn for_config(dirs: &Dirs, config: &TrustConfig, observer: Option<Observer>) -> Self {
        let key = Artifact::Tsl.cache_key(&config.tsl_url);
        Self::new(dirs, key.rsplit('/').next().unwrap_or(&key), observer)
    }

    fn new(dirs: &Dirs, id: &str, observer: Option<Observer>) -> Self {
        TslStateStore {
            path: dirs
                .state
                .join("tsl")
                .join(format!("{}.json", path_component(id))),
            observer,
        }
    }

    fn fail(&self, reason: impl fmt::Display) -> Error {
        Error::State {
            path: self.path.display().to_string(),
            reason: reason.to_string(),
        }
    }

    /// The stored state; none before the first run.
    fn read(&self) -> Result<Option<TslState>, Error> {
        let state = match std::fs::read(&self.path) {
            Ok(bytes) => Some(parse_tsl_state(&bytes).map_err(|error| {
                self.fail(format_args!(
                    "{error}; removing the file restarts the check from the next verified TSL, \
                     so an older list is not rejected until then"
                ))
            })?),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(self.fail(error)),
        };
        match &state {
            Some(s) => self.observe(format_args!("TSL state: #{} {}", s.sequence_number, s.id)),
            None => self.observe(format_args!("TSL state: none yet")),
        }
        Ok(state)
    }

    fn write(&self, state: &TslState) -> Result<(), Error> {
        if let Some(dir) = self.path.parent() {
            create_private_dir(dir).map_err(|error| self.fail(error))?;
        }
        let json = tsl_state_bytes(state).map_err(|error| self.fail(error))?;
        write_atomic(&self.path, &json).map_err(|error| self.fail(error))?;
        self.observe(format_args!(
            "TSL state: kept #{} {} in {}",
            state.sequence_number,
            state.id,
            self.path.display()
        ));
        Ok(())
    }

    fn observe(&self, message: fmt::Arguments<'_>) {
        if let Some(observer) = &self.observer {
            observer(message);
        }
    }
}

/// A TSL state file's content.
///
/// # Errors
///
/// The bytes are not the JSON of a [`TslState`].
pub fn parse_tsl_state(bytes: &[u8]) -> Result<TslState, serde_json::Error> {
    serde_json::from_slice(bytes)
}

/// The content of a TSL state file for `state`.
///
/// # Errors
///
/// `state` does not serialize.
pub fn tsl_state_bytes(state: &TslState) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(state)
}

/// Runs `verify` with the state an earlier run kept, so that an older list is rejected
/// (TSLSIG-053), and keeps the state of the list it verified when that changed. Taking
/// the state as a parameter keeps the wiring testable without the wall clock.
async fn with_kept_state<F, Fut>(
    state: Option<&TslStateStore>,
    verify: F,
) -> Result<Material, Error>
where
    F: FnOnce(Option<TslState>) -> Fut,
    Fut: std::future::Future<Output = Result<Material, Error>>,
{
    let stored = match state {
        Some(state) => state.read()?,
        None => None,
    };
    let material = verify(stored.clone()).await?;
    if let (Some(file), Some(current)) = (state, &material.tsl_state)
        && stored.as_ref() != Some(current)
    {
        file.write(current)?;
    }
    Ok(material)
}

/// Where the trust material came from, for the report.
#[derive(Clone, Debug, Serialize)]
pub struct TrustInfo {
    /// `http`, `cache` or `embedded`.
    pub source: &'static str,
    /// When the material was downloaded or last confirmed; absent when embedded.
    pub fetched_at: Option<String>,
    /// [`TrustInfo::fetched_at`] as a timestamp.
    #[serde(skip)]
    pub fetched_at_ts: Option<Timestamp>,
    /// The TSL's `NextUpdate`.
    pub tsl_next_update: Option<String>,
    /// [`TrustInfo::tsl_next_update`] as a timestamp.
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
    /// Narrowed to what a client without brainpool can use (`--nist-only`): the roots
    /// and TSL CAs whose own key is not brainpool, after a full verification.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub nist_only: bool,
}

impl Material {
    /// The material narrowed to the roots and TSL CAs a client without brainpool can use
    /// as anchors. Loading and verifying always use every algorithm: the root walk
    /// reaches the newer roots through brainpool cross certificates, and the TSL is
    /// signed on brainpool.
    #[must_use]
    pub fn nist_only(mut self) -> Material {
        let store = self.store.subset(ti_pki::algorithms::NIST);
        self.info.roots = store.len();
        self.info.intermediates = store.intermediates().len();
        self.info.nist_only = true;
        self.info.note = Some(
            "without brainpool: the roots and TSL CAs whose own key is not brainpool, \
             after a verification with brainpool"
                .into(),
        );
        self.store = Arc::new(store);
        self
    }
}

/// The bytes a load verified, with what the list says.
pub struct VerifiedSet {
    /// roots.json, the list and its detached files.
    pub set: TrustMaterial,
    /// The list, parsed from `set` and verified.
    pub verified: VerifiedTsl,
}

/// The verified TSL as a trust chain of its own: the list, its signer, the TSL signer CA.
#[derive(Clone, Debug, Serialize)]
pub struct TslTrust {
    /// `TSLSequenceNumber`.
    pub sequence_number: u64,
    /// The C.TSL.SIG certificate the list is signed with.
    pub signer: CertRef,
    /// `good` when the signer's OCSP status was queried or supplied, else absent.
    pub signer_ocsp: Option<&'static str>,
    /// The configured TSL signer CA that issued the signer.
    pub tsl_signer_ca: CertRef,
}

/// A certificate named in a report.
#[derive(Clone, Debug, Serialize)]
pub struct CertRef {
    /// Its subject's common name.
    pub common_name: String,
    /// Its `notAfter`, RFC 3339.
    pub not_after: String,
    /// The certificate.
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

/// What a [`Session`] tells its front end as it opens, for the user not to miss.
#[derive(Debug)]
pub enum Warning {
    /// The cache directory cannot be opened: the session caches in memory only.
    MemoryCache {
        /// The cache directory.
        dir: PathBuf,
        /// Why it cannot be opened.
        reason: String,
    },
    /// The TLS certificates of download servers are not checked ([`crate::Net::insecure`]);
    /// the material is still verified by its content.
    Insecure,
}

/// How an operation reaches trust material: over the network or not, and where the cache
/// is. One per invocation, so every load shares the cache and the transport.
pub struct Session<T = Http> {
    transport: Option<T>,
    /// The profile's directories; its state directory keeps the TSL state.
    dirs: Dirs,
    /// The profile's cache.
    cache: Option<Arc<FileCache>>,
    /// Stands in for the profile's cache when it cannot be opened.
    memory: Arc<MemoryCacheStore>,
    /// Downloads skip the TLS check ([`crate::Net::insecure`]).
    pub insecure: bool,
    /// Told what trust material and state the session reads and keeps.
    observer: Option<Observer>,
}

impl Session {
    /// A session over `dirs` with `client`'s HTTP settings; with `offline`, no request is
    /// ever made. `warn` hears what the user should know as the session opens.
    ///
    /// # Errors
    ///
    /// [`Error::Setup`] for HTTP settings that cannot be used, online only.
    pub fn new(
        client: &Client,
        dirs: &Dirs,
        offline: bool,
        warn: impl Fn(Warning),
    ) -> Result<Self, Error> {
        let cache = match FileCache::open(dirs.cache.clone()) {
            Ok(cache) => Some(Arc::new(cache)),
            Err(error) => {
                warn(Warning::MemoryCache {
                    dir: dirs.cache.clone(),
                    reason: error.to_string(),
                });
                None
            }
        };
        let insecure = client.net().insecure && !offline;
        if insecure {
            warn(Warning::Insecure);
        }
        let transport = if offline {
            None
        } else {
            Some(client.downloads()?)
        };
        Ok(Session {
            transport,
            dirs: dirs.clone(),
            cache,
            memory: Arc::default(),
            insecure,
            observer: client.observer().cloned(),
        })
    }
}

impl<T: Transport + Send + Sync> Session<T> {
    /// The transport for OCSP; `None` offline.
    pub fn transport(&self) -> Option<&T> {
        self.transport.as_ref()
    }

    /// Whether requests are made.
    pub fn is_offline(&self) -> bool {
        self.transport.is_none()
    }

    /// Tells the observer, if there is one.
    pub(crate) fn observe(&self, message: fmt::Arguments<'_>) {
        if let Some(observer) = &self.observer {
            observer(message);
        }
    }

    /// `env`'s trust material, loaded and verified with every algorithm, then narrowed to
    /// what a client without brainpool can use when `nist_only`; and the configuration to
    /// validate with.
    ///
    /// # Errors
    ///
    /// As [`Session::load`], and [`Error::Trust`] for a preset its tier does not admit.
    pub fn load_env(
        &self,
        env: Env,
        nist_only: bool,
        at: Option<Timestamp>,
    ) -> Result<(TrustConfig, Material), Error> {
        let full = trust_config(env, false);
        full.validate(env.tier()).map_err(Error::Trust)?;
        let material = self.load(&full, env.tier(), at)?;
        if nist_only {
            Ok((trust_config(env, true), material.nist_only()))
        } else {
            Ok((full, material))
        }
    }

    /// `config`'s trust material, verified at `at` or now: from the cache while fresh,
    /// else from the network (revalidating the cached copy). Offline, the cache or else
    /// the embedded roots. The TSL signer's OCSP status is queried online and at the
    /// current time only; it says nothing about another.
    ///
    /// # Errors
    ///
    /// [`Error::TrustLoad`] for material that cannot be had or fails verification,
    /// [`Error::TslRollback`] for a list older than the one kept, [`Error::State`] for a
    /// TSL state file that cannot be read or written, [`Error::Trust`] for an unusable
    /// configuration.
    pub fn load(
        &self,
        config: &TrustConfig,
        tier: Tier,
        at: Option<Timestamp>,
    ) -> Result<Material, Error> {
        self.load_with_state(config, tier, at, self.tsl_state(config, at).as_ref())
    }

    /// [`load`](Self::load) with the TSL state to check against and keep given, apart
    /// from the time it is verified at.
    fn load_with_state(
        &self,
        config: &TrustConfig,
        tier: Tier,
        at: Option<Timestamp>,
        state: Option<&TslStateStore>,
    ) -> Result<Material, Error> {
        block_on(with_kept_state(state, |stored| async move {
            let reach = Reach(self.transport.as_ref());
            let reloader = reloader(
                config,
                tier,
                AtTime::new(self.loader(config, reach), at),
                at_or_now(at),
                stored,
            )?;
            match &self.transport {
                Some(transport) if at.is_none() => {
                    let checker = OcspChecker::new(config, transport, Timestamp::now)
                        .with_store(self.store());
                    first_tick(&reloader.with_signer_status(checker))
                        .await
                        .map_err(Error::from)
                }
                Some(_) => first_tick(&reloader).await.map_err(Error::from),
                None => match first_tick(&reloader).await {
                    Err(Expired(ReloadError::Load(LoadError::Offline(_)))) => embedded(
                        config,
                        "offline and nothing cached: embedded roots only, no TSL",
                    ),
                    Err(Expired(ReloadError::TooOld { age })) => embedded(
                        config,
                        &format!(
                            "cached material is {} old: embedded roots only, no TSL",
                            crate::text::span(age.as_secs())
                        ),
                    ),
                    other => other.map_err(Error::from),
                },
            }
        }))
    }

    /// The list seen before guards against an older one, but only for the current time:
    /// a past instant may well need an older list.
    fn tsl_state(&self, config: &TrustConfig, at: Option<Timestamp>) -> Option<TslStateStore> {
        at.is_none()
            .then(|| TslStateStore::for_config(&self.dirs, config, self.observer.clone()))
    }

    /// The set [`load`](Self::load) verified, for a command that hands out its bytes.
    ///
    /// It is read back from the cache, and the rollback check only ever saw what `load`
    /// loaded. So the read never reaches the origin, even when the entry is stale, and the
    /// list it finds must be the one `material` says was verified: a list verified here
    /// alone, with no check of its sequence, could be an older one. Another process
    /// sharing the cache may have replaced the entry since, and that ends in an error.
    ///
    /// The published signer status is left out at `--at` (TSLDET-023), and when it is
    /// stale (TSLDET-015).
    ///
    /// # Errors
    ///
    /// [`Error::TrustLoad`] when no list was verified, the set is gone from the cache or is
    /// not the one verified.
    pub fn verified_set(
        &self,
        config: &TrustConfig,
        material: &Material,
        at: Option<Timestamp>,
    ) -> Result<VerifiedSet, Error> {
        let set = self.cached_set(config)?;
        let Some(loaded) = &material.tsl_state else {
            return Err(Error::TrustLoad(
                material
                    .info
                    .note
                    .clone()
                    .unwrap_or_else(|| "no verified TSL".into()),
            ));
        };
        let (set, verified) =
            verify_read_back(set, config, loaded, at, Timestamp::now()).map_err(|error| {
                Error::TrustLoad(match error {
                    ReadBackError::Unsigned => "the TSL came without its signature".into(),
                    ReadBackError::Tsl(error) => format!("TSL: {error}"),
                    ReadBackError::Replaced { cached } => format!(
                        "the cached TSL (#{} {}) is not the one this run verified (#{} {}): \
                         another process replaced it; run again",
                        cached.sequence_number, cached.id, loaded.sequence_number, loaded.id
                    ),
                })
            })?;
        Ok(VerifiedSet { set, verified })
    }

    /// The cached set under the age rules `load` applied, with no origin to ask: online,
    /// an entry past its age counts as stale, which keeps a stale status out as it did
    /// there; offline, any age is served, as it was there.
    fn cached_set(&self, config: &TrustConfig) -> Result<TrustMaterial, Error> {
        block_on(read_back(
            config,
            self.store(),
            Timestamp::now,
            self.is_offline(),
        ))
        .map_err(|error| match error {
            LoadError::Offline(_) => {
                Error::TrustLoad("offline and no TSL cached; run once without --offline".into())
            }
            LoadError::Transport(_) => Error::TrustLoad(
                "the cached TSL set is gone: another process removed it; run again".into(),
            ),
            error => Error::TrustLoad(error.to_string()),
        })
    }

    /// The cache on disk, or this session's memory when there is no cache directory:
    /// trust material and OCSP responses.
    pub fn store(&self) -> Store {
        match &self.cache {
            Some(cache) => Store::Profile(Arc::clone(cache)),
            None => Store::Memory(Arc::clone(&self.memory)),
        }
    }

    fn loader<N: Transport + Send + Sync>(
        &self,
        config: &TrustConfig,
        transport: N,
    ) -> CachingLoader<HttpLoader<N, Now>, Store, Now> {
        let store = self.store();
        CachingLoader::new(
            HttpLoader::new(config, transport, Timestamp::now),
            store,
            Timestamp::now,
            CachePolicy {
                offline: self.is_offline(),
                ..CachePolicy::default()
            },
        )
    }
}

/// The preset of `env`; with `nist_only`, validating without brainpool, as a client
/// without it would. Trust material is loaded with the full preset regardless
/// ([`Session::load_env`]).
pub fn trust_config(env: Env, nist_only: bool) -> TrustConfig {
    let config = TrustConfig::preset(env);
    if nist_only {
        TrustConfig {
            algorithms: std::borrow::Cow::Borrowed(ti_pki::algorithms::NIST),
            ..config
        }
    } else {
        config
    }
}

/// A first tick that left no material, with why.
struct Expired(ReloadError);

impl From<Expired> for Error {
    fn from(Expired(error): Expired) -> Self {
        match error {
            ReloadError::Verify(error) => {
                let rollback =
                    matches!(&error.tsl, Some(tsl) if tsl.code == TslCode::TslIdIncorrect);
                let message = format!("downloaded material failed verification: {error}");
                if rollback {
                    Error::TslRollback(message)
                } else {
                    Error::TrustLoad(message)
                }
            }
            error => Error::TrustLoad(error.to_string()),
        }
    }
}

fn reloader<L, N>(
    config: &TrustConfig,
    tier: Tier,
    loader: L,
    now: N,
    stored: Option<TslState>,
) -> Result<Reloader<L, N>, Error>
where
    L: Loader + Send + Sync,
    N: Fn() -> Timestamp + Send + Sync,
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
        Reloader::new(config.clone(), tier, loader, now, policy).map_err(Error::Trust)?;
    Ok(match stored {
        Some(state) => reloader.with_stored_tsl(state),
        None => reloader,
    })
}

async fn first_tick<L, N, R>(reloader: &Reloader<L, N, R>) -> Result<Material, Expired>
where
    L: Loader + Send + Sync,
    N: Fn() -> Timestamp + Send + Sync,
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

fn embedded(config: &TrustConfig, note: &str) -> Result<Material, Error> {
    let store = roots::load(config, Timestamp::now())
        .map_err(Error::Trust)?
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

/// The profile's cache, or memory when it cannot be opened.
pub enum Store {
    /// The cache directory.
    Profile(Arc<FileCache>),
    /// This session's memory.
    Memory(Arc<MemoryCacheStore>),
}

impl CacheStore for Store {
    async fn get(&self, key: &str) -> Result<Option<CacheEntry>, CacheError> {
        match self {
            Store::Profile(store) => store.get(key).await,
            Store::Memory(store) => store.get(key).await,
        }
    }

    async fn put(&self, key: &str, entry: &CacheEntry) -> Result<(), CacheError> {
        match self {
            Store::Profile(store) => store.put(key, entry).await,
            Store::Memory(store) => store.put(key, entry).await,
        }
    }
}

/// The session's transport, or [`NoNetwork`] without one: so that online and `--offline`
/// runs verify through one and the same reloader, and only differ in what they fall back to.
struct Reach<'a, T>(Option<&'a T>);

impl<T: Transport + Sync> Transport for Reach<'_, T> {
    async fn get(&self, req: &ArtifactRequest<'_>) -> Result<ArtifactResponse, TransportError> {
        match self.0 {
            Some(transport) => transport.get(req).await,
            None => NoNetwork.get(req).await,
        }
    }

    async fn post(&self, req: &PostRequest<'_>) -> Result<Vec<u8>, TransportError> {
        match self.0 {
            Some(transport) => transport.post(req).await,
            None => NoNetwork.post(req).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use ti_pki::load::{ResponseMeta, TransportErrorKind};

    use super::*;

    fn state(id: u64) -> TslState {
        TslState {
            id: format!("ID{id}"),
            sequence_number: id,
        }
    }

    fn profile(dir: &Path, name: Option<&str>) -> Dirs {
        Dirs {
            state: match name {
                Some(name) => dir.join("profiles").join(name),
                None => dir.to_owned(),
            },
            cache: dir.join("cache"),
        }
    }

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("ti-tsl-state-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn tsl_state_is_kept_without_any_setup() {
        let dir = scratch("setup");
        let p = profile(&dir, None);
        let store = TslStateStore::new(&p, "abc", None);
        assert_eq!(store.read().unwrap(), None, "none before the first run");
        store.write(&state(7)).unwrap();
        let file = p.state.join("tsl").join("abc.json");
        assert_eq!(
            parse_tsl_state(&std::fs::read(&file).unwrap()).unwrap(),
            state(7)
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    const CAPTURED_AT: &str = "2026-11-01T16:47:42Z";

    /// The production TSL of `spec/tsl-detached`, verified at the time it was captured
    /// through the same `reloader` and `first_tick` the commands use.
    fn verify_fixture(
        stored: Option<TslState>,
    ) -> impl std::future::Future<Output = Result<Material, Error>> {
        let set = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../spec/tsl-detached/testdata/prod/ECC-RSA_TSL");
        let config = TrustConfig::preset_prod();
        let transport = ti_pki::load::FileTransport::new(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../ti-pki/src/roots-prod.json"),
            set.with_extension("xml"),
            set.with_extension("sig"),
        );
        let at = at_or_now(Some(Timestamp::parse_rfc3339(CAPTURED_AT).unwrap()));
        async move {
            let reloader = reloader(
                &config,
                Tier::Prod,
                HttpLoader::new(&config, transport, Timestamp::now),
                at,
                stored,
            )?;
            first_tick(&reloader).await.map_err(Error::from)
        }
    }

    /// TSLSIG-053: a list older than the one a previous run kept is rejected, through the
    /// state file and the same wiring `Session::load` uses.
    #[test]
    fn tslsig_053_an_older_tsl_is_rejected_on_a_later_run() {
        let dir = scratch("later-run");
        let p = profile(&dir, Some("work"));
        let newer = state(20_000);
        TslStateStore::new(&p, "abc", None).write(&newer).unwrap();

        let later = TslStateStore::new(&p, "abc", None);
        let Err(error) = block_on(with_kept_state(Some(&later), verify_fixture)) else {
            panic!("a list older than the kept state must be rejected");
        };
        assert!(error.to_string().contains("tsl_id_incorrect"), "{error}");
        assert_eq!(
            later.read().unwrap(),
            Some(newer),
            "the state is not rewound"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_verified_tsl_is_kept_for_the_next_run() {
        let dir = scratch("kept");
        let p = profile(&dir, None);
        let first = block_on(with_kept_state(
            Some(&TslStateStore::new(&p, "abc", None)),
            verify_fixture,
        ))
        .unwrap();
        let verified = first.tsl_state.expect("the fixture's TSL state");
        let next = TslStateStore::new(&p, "abc", None);
        assert_eq!(
            next.read().unwrap(),
            Some(verified),
            "kept by the first run"
        );
        block_on(with_kept_state(Some(&next), verify_fixture))
            .expect("the same list again is not an error");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A session offline over a cache holding the fixture set, as a command sees it.
    fn fixture_session(p: &Dirs) -> Session {
        let session = Session {
            transport: None,
            dirs: p.clone(),
            cache: None,
            memory: Arc::default(),
            insecure: false,
            observer: None,
        };
        let set = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../spec/tsl-detached/testdata/prod/ECC-RSA_TSL");
        let config = TrustConfig::preset_prod();
        let transport = ti_pki::load::FileTransport::new(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../ti-pki/src/roots-prod.json"),
            set.with_extension("xml"),
            set.with_extension("sig"),
        );
        let filler = CachingLoader::new(
            HttpLoader::new(&config, transport, Timestamp::now),
            session.store(),
            Timestamp::now,
            CachePolicy::default(),
        );
        block_on(filler.load_all()).unwrap();
        session
    }

    /// The wiring of `Session::load`: it reads the kept state into the check, and keeps
    /// the state of the list it verified.
    #[test]
    fn session_load_checks_against_and_keeps_the_tsl_state() {
        let dir = scratch("session");
        let p = profile(&dir, None);
        let session = fixture_session(&p);
        let config = TrustConfig::preset_prod();
        let at = Some(Timestamp::parse_rfc3339(CAPTURED_AT).unwrap());
        let store = TslStateStore::for_config(&p, &config, None);

        let material = session
            .load_with_state(&config, Tier::Prod, at, Some(&store))
            .unwrap();
        assert_eq!(store.read().unwrap(), material.tsl_state, "kept");

        let newer = state(20_000);
        store.write(&newer).unwrap();
        let Err(error) = session.load_with_state(&config, Tier::Prod, at, Some(&store)) else {
            panic!("an older list must be rejected");
        };
        assert!(error.to_string().contains("tsl_id_incorrect"), "{error}");
        assert!(
            matches!(error, Error::TslRollback(_)),
            "a rollback, not a network problem: {error:?}"
        );
        assert_eq!(store.read().unwrap(), Some(newer));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// An origin that is down until told otherwise, then answers every request with
    /// `offered`, as HTTPS under `-k` or an interception proxy could.
    struct ScriptedOrigin {
        down: AtomicBool,
        requests: AtomicUsize,
        offered: &'static [u8],
    }

    impl Transport for ScriptedOrigin {
        async fn get(&self, _: &ArtifactRequest<'_>) -> Result<ArtifactResponse, TransportError> {
            self.requests.fetch_add(1, Ordering::SeqCst);
            if self.down.load(Ordering::SeqCst) {
                return Err(TransportError {
                    kind: TransportErrorKind::Network,
                    message: "connection refused".into(),
                    retryable: true,
                });
            }
            Ok(ArtifactResponse::Fresh {
                body: self.offered.to_vec(),
                meta: ResponseMeta {
                    etag: Some("\"offered\"".into()),
                    last_modified: None,
                    max_age: None,
                    source: Source::Http,
                },
            })
        }

        async fn post(&self, req: &PostRequest<'_>) -> Result<Vec<u8>, TransportError> {
            NoNetwork.post(req).await
        }
    }

    /// A session whose cache holds the fixture set past `max_age`, within
    /// `stale_if_error`, and whose origin is down: its load serves the entries stale, so
    /// they are still stale when the command reads them.
    fn session_over_a_stale_cache(p: &Dirs, offered: &'static [u8]) -> Session<ScriptedOrigin> {
        let session = Session {
            transport: Some(ScriptedOrigin {
                down: AtomicBool::new(true),
                requests: AtomicUsize::new(0),
                offered,
            }),
            dirs: p.clone(),
            cache: None,
            memory: Arc::default(),
            insecure: false,
            observer: None,
        };
        let config = TrustConfig::preset_prod();
        let filler = fixture_loader(&session.store(), &config);
        block_on(filler.load_all()).unwrap();
        for artifact in [Artifact::Roots, Artifact::Tsl, Artifact::TslSignature] {
            let key = filler.cache_key(artifact);
            let store = session.store();
            let mut entry = block_on(store.get(&key)).unwrap().unwrap();
            entry.meta.fetched_at = Timestamp::now() - Duration::from_hours(2);
            block_on(store.put(&key, &entry)).unwrap();
        }
        session
    }

    fn fixture_loader(
        store: &Store,
        config: &TrustConfig,
    ) -> CachingLoader<HttpLoader<ti_pki::load::FileTransport, Now>, Store, Now> {
        let set = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../spec/tsl-detached/testdata/prod/ECC-RSA_TSL");
        let transport = ti_pki::load::FileTransport::new(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../ti-pki/src/roots-prod.json"),
            set.with_extension("xml"),
            set.with_extension("sig"),
        );
        let store = match store {
            Store::Profile(cache) => Store::Profile(Arc::clone(cache)),
            Store::Memory(memory) => Store::Memory(Arc::clone(memory)),
        };
        CachingLoader::new(
            HttpLoader::new(config, transport, Timestamp::now),
            store,
            Timestamp::now,
            CachePolicy::default(),
        )
    }

    /// TSLSIG-053: what a command uses is read after the load, and a stale entry must not
    /// send that read to the origin, whose answer the rollback check would never see.
    #[test]
    fn tslsig_053_reading_after_load_does_not_reach_the_origin_when_the_entry_is_stale() {
        let dir = scratch("read-back");
        let p = profile(&dir, None);
        let session = session_over_a_stale_cache(&p, b"<older/>");
        let config = TrustConfig::preset_prod();
        let at = Some(Timestamp::parse_rfc3339(CAPTURED_AT).unwrap());
        let material = session
            .load_with_state(&config, Tier::Prod, at, None)
            .expect("the stale set serves the load");

        let origin = session.transport().unwrap();
        origin.down.store(false, Ordering::SeqCst);
        origin.requests.store(0, Ordering::SeqCst);
        let read = session.verified_set(&config, &material, at).unwrap();
        assert_eq!(origin.requests.load(Ordering::SeqCst), 0);
        assert_eq!(
            Some(TslState::of(&read.verified.tsl)),
            material.tsl_state,
            "the list the load verified"
        );
        assert_ne!(read.set.tsl, b"<older/>");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// TSLSIG-053: a list in the cache that is not the one the load verified, here one
    /// older than it, never reaches a command, even though its signature is good.
    #[test]
    fn tslsig_053_a_cached_list_other_than_the_verified_one_is_refused() {
        let dir = scratch("other-list");
        let p = profile(&dir, None);
        let session = session_over_a_stale_cache(&p, b"<older/>");
        let config = TrustConfig::preset_prod();
        let at = Some(Timestamp::parse_rfc3339(CAPTURED_AT).unwrap());
        let mut material = session
            .load_with_state(&config, Tier::Prod, at, None)
            .unwrap();
        material.tsl_state = Some(state(20_000));
        let Err(error) = session.verified_set(&config, &material, at) else {
            panic!("the cached list is not the verified one");
        };
        assert!(error.to_string().contains("run again"), "{error}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// With the cached set past the hard expiry `load` falls back to the embedded roots
    /// and verifies no list; the cached one must not be used then.
    #[test]
    fn no_list_is_read_after_a_load_that_verified_none() {
        let dir = scratch("no-list");
        let p = profile(&dir, None);
        let session = session_over_a_stale_cache(&p, b"<older/>");
        let config = TrustConfig::preset_prod();
        let at = Some(Timestamp::parse_rfc3339(CAPTURED_AT).unwrap());
        let material = embedded(&config, "cached material is 2 days old").unwrap();
        let Err(error) = session.verified_set(&config, &material, at) else {
            panic!("no list was verified");
        };
        assert!(error.to_string().contains("2 days old"), "{error}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// TSLDET-023: the published status says nothing about another time.
    #[test]
    fn tsldet_023_the_verified_set_at_another_time_has_no_signer_status() {
        let dir = scratch("no-status");
        let p = profile(&dir, None);
        let session = session_over_a_stale_cache(&p, b"<older/>");
        let config = TrustConfig::preset_prod();
        let at = Some(Timestamp::parse_rfc3339(CAPTURED_AT).unwrap());
        let filler = fixture_loader(&session.store(), &config);
        let key = filler.cache_key(Artifact::TslSignerStatus);
        let store = session.store();
        let entry = CacheEntry {
            body: b"a status".to_vec(),
            meta: block_on(store.get(&filler.cache_key(Artifact::Tsl)))
                .unwrap()
                .unwrap()
                .meta,
        };
        block_on(store.put(&key, &entry)).unwrap();
        let material = session
            .load_with_state(&config, Tier::Prod, at, None)
            .unwrap();
        let read = session.verified_set(&config, &material, at).unwrap();
        assert!(read.set.detached.unwrap().signer_status.is_none());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Puts `body` in the cache as the published status, fetched `age` ago.
    fn cache_status<T: Transport + Send + Sync>(
        session: &Session<T>,
        config: &TrustConfig,
        body: &[u8],
        age: Duration,
    ) {
        let filler = fixture_loader(&session.store(), config);
        let store = session.store();
        let mut meta = block_on(store.get(&filler.cache_key(Artifact::Tsl)))
            .unwrap()
            .unwrap()
            .meta;
        meta.fetched_at = Timestamp::now() - age;
        let entry = CacheEntry {
            body: body.to_vec(),
            meta,
        };
        block_on(store.put(&filler.cache_key(Artifact::TslSignerStatus), &entry)).unwrap();
    }

    fn cached_status<T: Transport + Send + Sync>(
        session: &Session<T>,
        config: &TrustConfig,
    ) -> Option<Vec<u8>> {
        let set = session.cached_set(config).unwrap();
        set.detached
            .and_then(|detached| detached.signer_status)
            .map(|(body, _)| body)
    }

    /// TSLDET-015: online, a status past its age is what `load` dropped, and the set a
    /// command hands out must not bring it back; garbage in it must not stop the command
    /// either, as nothing reads it.
    #[test]
    fn tsldet_015_a_stale_status_is_left_out_of_the_set_read_back() {
        let dir = scratch("stale-status");
        let p = profile(&dir, None);
        let session = session_over_a_stale_cache(&p, b"<older/>");
        let config = TrustConfig::preset_prod();
        let limit = CachePolicy::default().max_age;

        cache_status(&session, &config, b"not a status", limit);
        assert_eq!(cached_status(&session, &config), None, "at the limit");

        cache_status(&session, &config, b"a status", limit / 2);
        assert_eq!(
            cached_status(&session, &config).as_deref(),
            Some(&b"a status"[..]),
            "under the limit it is what load used"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Offline, `load` serves the cache at any age and the status's own `producedAt`
    /// decides; the read back keeps to the same set.
    #[test]
    fn offline_the_set_read_back_keeps_a_status_of_any_age() {
        let dir = scratch("offline-status");
        let p = profile(&dir, None);
        let session = fixture_session(&p);
        let config = TrustConfig::preset_prod();
        cache_status(&session, &config, b"a status", Duration::from_hours(48));
        assert_eq!(
            cached_status(&session, &config).as_deref(),
            Some(&b"a status"[..])
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Online, a set gone from the cache since the load is another process's doing: the
    /// error says so, not that the run was offline.
    #[test]
    fn a_set_gone_from_the_cache_since_the_load_says_so() {
        let dir = scratch("gone");
        let p = profile(&dir, None);
        let session = Session {
            transport: Some(ScriptedOrigin {
                down: AtomicBool::new(true),
                requests: AtomicUsize::new(0),
                offered: b"<unused/>",
            }),
            dirs: p.clone(),
            cache: None,
            memory: Arc::default(),
            insecure: false,
            observer: None,
        };
        let Err(error) = session.cached_set(&TrustConfig::preset_prod()) else {
            panic!("nothing is cached");
        };
        let message = error.to_string();
        assert!(message.contains("run again"), "{message}");
        assert!(!message.contains("offline"), "{message}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A past instant may need an older list, so `--at` neither checks nor keeps the state;
    /// the current time does both.
    #[test]
    fn session_load_selects_the_tsl_state_only_for_the_current_time() {
        let dir = scratch("selection");
        let p = profile(&dir, None);
        let session = fixture_session(&p);
        let config = TrustConfig::preset_prod();
        assert_eq!(
            session.tsl_state(&config, None).map(|store| store.path),
            Some(TslStateStore::for_config(&p, &config, None).path)
        );
        assert!(session.tsl_state(&config, Some(Timestamp(1))).is_none());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn no_state_is_kept_or_checked_without_a_store() {
        assert!(block_on(with_kept_state(None, verify_fixture)).is_ok());
    }

    #[test]
    fn a_corrupt_tsl_state_is_an_error_naming_the_file() {
        let dir = scratch("corrupt");
        let p = profile(&dir, None);
        let file = p.state.join("tsl").join("abc.json");
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(&file, b"{\"id\":").unwrap();
        let Err(error) = TslStateStore::new(&p, "abc", None).read() else {
            panic!("a corrupt state must not read as none");
        };
        assert!(matches!(error, Error::State { .. }), "{error:?}");
        let message = error.to_string();
        assert!(message.contains(&file.display().to_string()));
        assert!(
            message.contains(
                "removing the file restarts the check from the next verified TSL, so an older list is not rejected until then"
            ),
            "{message}"
        );
        assert_eq!(std::fs::read(&file).unwrap(), b"{\"id\":", "left as it is");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn an_unwritable_state_directory_is_an_error() {
        let dir = scratch("unwritable");
        let p = profile(&dir, None);
        std::fs::create_dir_all(&p.state).unwrap();
        std::fs::write(p.state.join("tsl"), b"a file where the directory belongs").unwrap();
        let Err(error) = TslStateStore::new(&p, "abc", None).write(&state(1)) else {
            panic!("a failed write must not pass silently");
        };
        assert!(matches!(error, Error::State { .. }), "{error:?}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Only a missing file means no state: a read that fails otherwise must not switch the
    /// rollback check off.
    #[test]
    fn a_tsl_state_that_cannot_be_read_is_an_error_not_no_state() {
        let dir = scratch("unreadable");
        let p = profile(&dir, None);
        let file = p.state.join("tsl").join("abc.json");
        std::fs::create_dir_all(&file).unwrap();
        let Err(error) = TslStateStore::new(&p, "abc", None).read() else {
            panic!("a directory at the path must not read as none");
        };
        assert!(matches!(error, Error::State { .. }), "{error:?}");

        std::fs::remove_dir_all(p.state.join("tsl")).unwrap();
        std::fs::write(p.state.join("tsl"), b"in the way").unwrap();
        let Err(error) = TslStateStore::new(&p, "abc", None).read() else {
            panic!("tsl being a file must not read as none");
        };
        assert!(matches!(error, Error::State { .. }), "{error:?}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn profiles_keep_separate_tsl_state() {
        let dir = scratch("profiles");
        let (a, b) = (profile(&dir, Some("a")), profile(&dir, Some("b")));
        TslStateStore::new(&a, "abc", None)
            .write(&state(3))
            .unwrap();
        assert_eq!(TslStateStore::new(&b, "abc", None).read().unwrap(), None);
        assert_eq!(
            TslStateStore::new(&a, "other", None).read().unwrap(),
            None,
            "keyed by the TSL's URL"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
