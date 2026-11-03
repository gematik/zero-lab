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

//! Trust material for commands: roots.json and the TSL, downloaded or cached, and
//! verified by ti-pki either way: the roots against the embedded anchor, the TSL against
//! the embedded TSL signer CA, its `NextUpdate`, the list seen before and, online, its
//! signer's OCSP status (`spec/tsl-xmldsig`). The embedded roots alone when offline with
//! nothing cached.

#[cfg(test)]
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;
use ti_pki::load::{
    Artifact, ArtifactRequest, ArtifactResponse, CacheEntry, CacheError, CachePolicy, CacheStore,
    CachingLoader, Detached, HttpLoader, LoadError, Loader, MemoryCacheStore, Meta, PostRequest,
    ReloadError, ReloadOutcome, ReloadPolicy, Reloader, Source, SystemClock, Transport,
    TransportError, TransportErrorKind,
};
use ti_pki::ocsp::OcspChecker;
use ti_pki::revocation::RevocationChecker;
use ti_pki::tsl_signature::TslState;
use ti_pki::{Clock, Tier, Timestamp, TrustConfig, TrustStore, roots};

use crate::block::block_on;
use crate::cli::GlobalArgs;
use crate::error::CliError;
use crate::file_cache::FileCache;
use crate::files::{create_private_dir, path_component, write_atomic};
use crate::http::{self, Http};
use crate::output::{Output, warning};
use crate::profile::Profile;

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

/// The `Id` and sequence number of the TSL last used from one URL, kept as a plain file
/// in the profile's state directory: `cache clear` leaves it, so an older list stays
/// rejected (TSLSIG-053). It needs no setup, and it is never dropped silently: a file
/// that cannot be read, parsed or written is an error, since a rollback check that
/// quietly stopped working would be worse than a command that stops.
struct TslStateStore {
    path: PathBuf,
    verbose: u8,
}

impl TslStateStore {
    /// The state of `config`'s TSL, keyed as its cache entry is.
    fn for_config(profile: &Profile, config: &TrustConfig, verbose: u8) -> Self {
        let key = Artifact::Tsl.cache_key(&config.tsl_url);
        Self::new(profile, key.rsplit('/').next().unwrap_or(&key), verbose)
    }

    fn new(profile: &Profile, id: &str, verbose: u8) -> Self {
        TslStateStore {
            path: profile
                .state_dir
                .join("tsl")
                .join(format!("{}.json", path_component(id))),
            verbose,
        }
    }

    fn fail(&self, reason: impl std::fmt::Display) -> CliError {
        CliError::State {
            path: self.path.display().to_string(),
            reason: reason.to_string(),
        }
    }

    /// The stored state; none before the first run.
    fn read(&self) -> Result<Option<TslState>, CliError> {
        let state = match std::fs::read(&self.path) {
            Ok(bytes) => Some(parse_tsl_state(&bytes).map_err(|error| self.fail(error))?),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(self.fail(error)),
        };
        match &state {
            Some(s) => self.verbose(format_args!("TSL state: #{} {}", s.sequence_number, s.id)),
            None => self.verbose("TSL state: none yet"),
        }
        Ok(state)
    }

    fn write(&self, state: &TslState) -> Result<(), CliError> {
        if let Some(dir) = self.path.parent() {
            create_private_dir(dir).map_err(|error| self.fail(error))?;
        }
        let json = serde_json::to_vec(state).map_err(|error| self.fail(error))?;
        write_atomic(&self.path, &json).map_err(|error| self.fail(error))?;
        self.verbose(format_args!(
            "TSL state: kept #{} {} in {}",
            state.sequence_number,
            state.id,
            self.path.display()
        ));
        Ok(())
    }

    fn verbose(&self, message: impl std::fmt::Display) {
        if self.verbose >= 1 {
            crate::output::diagnostic(message);
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

/// Runs `verify` with the state an earlier run kept, so that an older list is rejected
/// (TSLSIG-053), and keeps the state of the list it verified when that changed. Taking
/// the state as a parameter keeps the wiring testable without the wall clock.
async fn with_kept_state<F, Fut>(
    state: Option<&TslStateStore>,
    verify: F,
) -> Result<Material, CliError>
where
    F: FnOnce(Option<TslState>) -> Fut,
    Fut: std::future::Future<Output = Result<Material, CliError>>,
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

/// The verified TSL as a trust chain of its own: the list, its signer, the TSL signer CA.
#[derive(Serialize)]
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
    /// The profile in effect; none when it cannot be resolved, and then nothing is kept.
    profile: Option<Profile>,
    /// The profile's cache.
    cache: Option<Arc<FileCache>>,
    /// Stands in for the profile's cache when it cannot be opened.
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
        let profile = Profile::resolve(global)?;
        let cache = match FileCache::open(&profile) {
            Ok(cache) => Some(Arc::new(cache)),
            Err(error) => {
                warning(format_args!(
                    "cache {}: {error}; caching in memory only",
                    profile.cache_dir.display()
                ));
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
            profile: Some(profile),
            cache,
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
    ) -> Result<Material, CliError> {
        let clock = At(at);
        block_on(with_kept_state(state, |stored| async move {
            if let Some(transport) = &self.transport {
                let reloader = reloader(
                    config,
                    tier,
                    AtTime::new(self.loader(config, transport), at),
                    clock,
                    stored,
                )?;
                if at.is_none() {
                    let checker =
                        OcspChecker::new(config, transport, SystemClock).with_store(self.store());
                    first_tick(&reloader.with_signer_status(checker)).await
                } else {
                    first_tick(&reloader).await
                }
                .map_err(CliError::from)
            } else {
                let reloader = reloader(
                    config,
                    tier,
                    AtTime::new(self.loader(config, NoNetwork), at),
                    clock,
                    stored,
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
            }
        }))
    }

    /// The list seen before guards against an older one, but only for the current time:
    /// a past instant may well need an older list.
    fn tsl_state(&self, config: &TrustConfig, at: Option<Timestamp>) -> Option<TslStateStore> {
        match (&self.profile, at) {
            (Some(profile), None) => Some(TslStateStore::for_config(profile, config, self.verbose)),
            _ => None,
        }
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

    /// The whole set as loaded, for a bundle. Call after [`load`](Self::load).
    pub fn trust_material(
        &self,
        config: &TrustConfig,
    ) -> Result<ti_pki::load::TrustMaterial, CliError> {
        block_on(async {
            match &self.transport {
                Some(transport) => self.loader(config, transport).load_all().await,
                None => self.loader(config, NoNetwork).load_all().await,
            }
        })
        .map_err(|error| CliError::TrustLoad(error.to_string()))
    }

    /// The list's detached files, as loaded from the environment's automated download
    /// point (`spec/tsl-detached`). Call after [`load`](Self::load).
    pub fn tsl_detached(&self, config: &TrustConfig) -> Result<Detached, CliError> {
        block_on(async {
            match &self.transport {
                Some(transport) => self.loader(config, transport).load_detached().await,
                None => self.loader(config, NoNetwork).load_detached().await,
            }
        })
        .map_err(|error| CliError::TrustLoad(error.to_string()))
    }

    /// The cache on disk, or this session's memory when there is no cache directory:
    /// trust material and OCSP responses.
    pub fn store(&self) -> Store {
        match &self.cache {
            Some(cache) => Store::Profile(Arc::clone(cache)),
            None => Store::Memory(Arc::clone(&self.memory)),
        }
    }

    fn loader<T: Transport + Send + Sync>(
        &self,
        config: &TrustConfig,
        transport: T,
    ) -> CachingLoader<HttpLoader<T, SystemClock>, Store, SystemClock> {
        let store = self.store();
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

/// A loader for a validation at `--at`: the published signer status is left out, since
/// it says nothing about another time (`spec/tsl-detached` TSLDET-023).
struct AtTime<L> {
    inner: L,
    past: bool,
}

impl<L> AtTime<L> {
    fn new(inner: L, at: Option<Timestamp>) -> Self {
        AtTime {
            inner,
            past: at.is_some(),
        }
    }
}

impl<L: Loader + Send + Sync> Loader for AtTime<L> {
    async fn fetch(
        &self,
        artifact: Artifact,
        cond: ti_pki::load::Conditional<'_>,
    ) -> Result<ti_pki::load::Fetched, LoadError> {
        if self.past && artifact == Artifact::TslSignerStatus {
            return Err(LoadError::Unavailable(artifact));
        }
        self.inner.fetch(artifact, cond).await
    }

    fn cache_key(&self, artifact: Artifact) -> String {
        self.inner.cache_key(artifact)
    }

    async fn revalidate(&self) -> Result<(), LoadError> {
        self.inner.revalidate().await
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

/// The profile's cache, or memory when it cannot be opened.
pub enum Store {
    Profile(Arc<FileCache>),
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

#[cfg(test)]
mod tests {
    use super::*;

    fn state(id: u64) -> TslState {
        TslState {
            id: format!("ID{id}"),
            sequence_number: id,
        }
    }

    fn profile(dir: &Path, name: Option<&str>) -> Profile {
        Profile {
            name: name.map(str::to_owned),
            state_dir: match name {
                Some(name) => dir.join("profiles").join(name),
                None => dir.to_owned(),
            },
            cache_dir: dir.join("cache"),
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
        let store = TslStateStore::new(&p, "abc", 0);
        assert_eq!(store.read().unwrap(), None, "none before the first run");
        store.write(&state(7)).unwrap();
        let file = p.state_dir.join("tsl").join("abc.json");
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
    ) -> impl std::future::Future<Output = Result<Material, CliError>> {
        let set = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../spec/tsl-detached/testdata/prod/ECC-RSA_TSL");
        let config = TrustConfig::preset_prod();
        let transport = ti_pki::load::FileTransport::new(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../ti-pki/src/roots-prod.json"),
            set.with_extension("xml"),
            set.with_extension("sig"),
        );
        let at = At(Some(Timestamp::parse_rfc3339(CAPTURED_AT).unwrap()));
        async move {
            let reloader = reloader(
                &config,
                Tier::Prod,
                HttpLoader::new(&config, transport, SystemClock),
                at,
                stored,
            )?;
            first_tick(&reloader).await.map_err(CliError::from)
        }
    }

    /// TSLSIG-053: a list older than the one a previous run kept is rejected, through the
    /// state file and the same wiring `Session::load` uses.
    #[test]
    fn an_older_tsl_is_rejected_on_a_later_run() {
        let dir = scratch("later-run");
        let p = profile(&dir, Some("work"));
        let newer = state(20_000);
        TslStateStore::new(&p, "abc", 0).write(&newer).unwrap();

        let later = TslStateStore::new(&p, "abc", 0);
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
            Some(&TslStateStore::new(&p, "abc", 0)),
            verify_fixture,
        ))
        .unwrap();
        let verified = first.tsl_state.expect("the fixture's TSL state");
        let next = TslStateStore::new(&p, "abc", 0);
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
    fn fixture_session(p: &Profile) -> Session {
        let session = Session {
            transport: None,
            profile: Some(p.clone()),
            cache: None,
            memory: Arc::default(),
            insecure: false,
            verbose: 0,
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
            HttpLoader::new(&config, transport, SystemClock),
            session.store(),
            SystemClock,
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
        let store = TslStateStore::for_config(&p, &config, 0);

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
        assert_eq!(store.read().unwrap(), Some(newer));
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
        let file = p.state_dir.join("tsl").join("abc.json");
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(&file, b"{\"id\":").unwrap();
        let Err(error) = TslStateStore::new(&p, "abc", 0).read() else {
            panic!("a corrupt state must not read as none");
        };
        assert_eq!(error.kind(), "state_file_failed");
        assert!(error.to_string().contains(&file.display().to_string()));
        assert_eq!(std::fs::read(&file).unwrap(), b"{\"id\":", "left as it is");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn an_unwritable_state_directory_is_an_error() {
        let dir = scratch("unwritable");
        let p = profile(&dir, None);
        std::fs::create_dir_all(&p.state_dir).unwrap();
        std::fs::write(
            p.state_dir.join("tsl"),
            b"a file where the directory belongs",
        )
        .unwrap();
        let Err(error) = TslStateStore::new(&p, "abc", 0).write(&state(1)) else {
            panic!("a failed write must not pass silently");
        };
        assert_eq!(error.kind(), "state_file_failed");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn profiles_keep_separate_tsl_state() {
        let dir = scratch("profiles");
        let (a, b) = (profile(&dir, Some("a")), profile(&dir, Some("b")));
        TslStateStore::new(&a, "abc", 0).write(&state(3)).unwrap();
        assert_eq!(TslStateStore::new(&b, "abc", 0).read().unwrap(), None);
        assert_eq!(
            TslStateStore::new(&a, "other", 0).read().unwrap(),
            None,
            "keyed by the TSL's URL"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
