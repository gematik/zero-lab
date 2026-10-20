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
use crate::error::{CliError, StoreFile};
use crate::http::{self, Http};
use crate::output::{Output, warning};
use crate::paths;
use crate::store::StoreCache;
use crate::store::profile::{ProfileStore, Selected};
use ti_store::store::StoreError;
use ti_store::store::registry::TSL_STATE;

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

/// The `Id` and sequence number of the TSL last used from one URL, sealed in the
/// profile's state: `cache clear` leaves it, so an older list stays rejected (TSLSIG-053).
/// Without a keyring it is not kept, with a warning that names the fix; a state or
/// keyring that does not open is an error (STORE-128). Files of earlier versions in the
/// legacy state directory are read while the profile has no keyring, and moved into the
/// store once it has one.
struct TslStateStore {
    store: Option<ProfileStore>,
    profile: String,
    id: String,
    legacy: Option<PathBuf>,
    verbose: u8,
}

/// The payload's version (STORE-110), before the state as JSON.
const TSL_STATE_V1: u8 = 1;

impl TslStateStore {
    /// The state of `config`'s TSL, keyed as its cache entry is.
    fn for_config(
        selected: &Selected,
        config: &TrustConfig,
        verbose: u8,
    ) -> Result<Self, CliError> {
        let key = Artifact::Tsl.cache_key(&config.tsl_url);
        let id = key.rsplit('/').next().unwrap_or(&key).to_owned();
        let legacy = paths::legacy_state_dir()
            .ok()
            .map(|dir| dir.join("tsl").join(format!("{id}.json")));
        Self::open(selected, id, legacy, verbose)
    }

    fn open(
        selected: &Selected,
        id: String,
        legacy: Option<PathBuf>,
        verbose: u8,
    ) -> Result<Self, CliError> {
        let store = if selected.has_keyring() {
            Some(selected.open_state()?)
        } else {
            None
        };
        let state = TslStateStore {
            store,
            profile: selected.profile.name.clone(),
            id,
            legacy,
            verbose,
        };
        state.import_legacy()?;
        Ok(state)
    }

    /// Moves a file of an earlier version into the store, once.
    fn import_legacy(&self) -> Result<(), CliError> {
        let (Some(_), Some(path)) = (&self.store, &self.legacy) else {
            return Ok(());
        };
        let Some(old) = read_legacy(path) else {
            return Ok(());
        };
        if self.get()?.is_none() {
            self.put(&old)?;
            self.verbose(format_args!(
                "TSL state: moved {} into the profile's state",
                path.display()
            ));
        }
        let _ = std::fs::remove_file(path);
        Ok(())
    }

    fn get(&self) -> Result<Option<TslState>, CliError> {
        let Some(store) = &self.store else {
            return Ok(None);
        };
        match block_on(store.get(&TSL_STATE, self.id.as_bytes(), crate::store::now())) {
            Ok(stored) => Ok(stored
                .payload
                .split_first()
                .filter(|(v, _)| **v == TSL_STATE_V1)
                .and_then(|(_, json)| serde_json::from_slice(json).ok())),
            Err(StoreError::NotFound) => Ok(None),
            Err(error) => Err(self.fail(error)),
        }
    }

    fn put(&self, state: &TslState) -> Result<(), CliError> {
        let Some(store) = &self.store else {
            return Ok(());
        };
        let mut payload = vec![TSL_STATE_V1];
        payload.extend(serde_json::to_vec(state)?);
        block_on(store.put(
            &TSL_STATE,
            self.id.as_bytes(),
            &payload,
            &[],
            None,
            crate::store::now(),
        ))
        .map(drop)
        .map_err(|error| self.fail(error))
    }

    fn fail(&self, error: StoreError) -> CliError {
        CliError::Store {
            profile: self.profile.clone(),
            file: StoreFile::Record,
            path: "tsl.state".into(),
            error,
        }
    }

    /// The stored state; none before the first run.
    fn read(&self) -> Result<Option<TslState>, CliError> {
        let state = if self.store.is_some() {
            self.get()?
        } else {
            self.legacy.as_deref().and_then(read_legacy)
        };
        match &state {
            Some(s) => self.verbose(format_args!("TSL state: #{} {}", s.sequence_number, s.id)),
            None => self.verbose("TSL state: none yet"),
        }
        Ok(state)
    }

    fn write(&self, state: &TslState) -> Result<(), CliError> {
        if self.store.is_none() {
            warning(format_args!(
                "profile {} has no keyring: the TSL seen now is not kept, so an older list is \
                 not rejected next time; run `ti profile create`",
                self.profile
            ));
            return Ok(());
        }
        self.put(state)?;
        self.verbose(format_args!(
            "TSL state: kept #{} {}",
            state.sequence_number, state.id
        ));
        Ok(())
    }

    fn verbose(&self, message: impl std::fmt::Display) {
        if self.verbose >= 1 {
            crate::output::diagnostic(message);
        }
    }
}

/// A TSL state file of an earlier version; an unreadable one counts as none.
fn read_legacy(path: &std::path::Path) -> Option<TslState> {
    serde_json::from_slice(&std::fs::read(path).ok()?).ok()
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
    /// The profile in effect; none when it cannot be resolved, and then nothing is kept.
    selected: Option<Selected>,
    /// The profile's cache.
    cache: Option<Arc<StoreCache>>,
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
        let selected = Selected::resolve(global)?;
        let cache = match selected.open_cache() {
            Ok(store) => Some(Arc::new(StoreCache(store))),
            Err(error) => {
                warning(format_args!("{error}; caching in memory only"));
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
            selected: Some(selected),
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
        let clock = At(at);
        // The list seen before guards against an older one, but only for the current
        // time: a past instant may well need an older list.
        let state = match (&self.selected, at) {
            (Some(selected), None) => {
                Some(TslStateStore::for_config(selected, config, self.verbose)?)
            }
            _ => None,
        };
        let stored = match &state {
            Some(state) => state.read()?,
            None => None,
        };
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
                file.write(current)?;
            }
            Ok(material)
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
    Profile(Arc<StoreCache>),
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
    use crate::store::profile::tests::{TestProfile, with_keyring};

    fn state(id: u64) -> TslState {
        TslState {
            id: format!("ID{id}"),
            sequence_number: id,
        }
    }

    /// STORE-023: without a keyring the TSL state of an earlier version is read and never
    /// written or removed.
    #[test]
    fn tsl_state_without_a_keyring_reads_the_legacy_file_only() {
        let p = TestProfile::new("tsl-nokeyring");
        let legacy = p.dir.join("legacy.json");
        std::fs::write(&legacy, serde_json::to_vec(&state(7)).unwrap()).unwrap();
        let s = TslStateStore::open(&p.selected, "abc".into(), Some(legacy.clone()), 0).unwrap();
        assert_eq!(s.read().unwrap(), Some(state(7)));
        s.write(&state(8)).unwrap();
        assert_eq!(s.read().unwrap(), Some(state(7)), "not written");
        assert!(legacy.exists());
        assert!(
            !Path::new(p.selected.state_path()).exists(),
            "no state.db made"
        );
    }

    /// TSLSIG-053 with STORE-023: with a keyring the state is sealed in the profile, the
    /// legacy file moved into it and removed.
    #[test]
    fn tsl_state_with_a_keyring_is_sealed_and_takes_over_the_legacy_file() {
        let p = with_keyring("tsl-keyring");
        let legacy = p.dir.join("legacy.json");
        std::fs::write(&legacy, serde_json::to_vec(&state(7)).unwrap()).unwrap();
        let s = TslStateStore::open(&p.selected, "abc".into(), Some(legacy.clone()), 0).unwrap();
        assert!(!legacy.exists(), "moved");
        assert_eq!(s.read().unwrap(), Some(state(7)));
        s.write(&state(9)).unwrap();
        let again = TslStateStore::open(&p.selected, "abc".into(), None, 0).unwrap();
        assert_eq!(again.read().unwrap(), Some(state(9)));
        let other = TslStateStore::open(&p.selected, "other".into(), None, 0).unwrap();
        assert_eq!(other.read().unwrap(), None, "keyed by the TSL's URL");

        // a new record may still be in the WAL rather than the database file
        for suffix in ["", "-wal"] {
            let path = format!("{}{suffix}", p.selected.state_path());
            let raw = std::fs::read(&path).unwrap_or_default();
            assert!(
                !raw.windows(3).any(|w| w == b"ID9"),
                "no state in clear in {path}"
            );
        }
        let wal = std::fs::read(format!("{}-wal", p.selected.state_path())).unwrap_or_default();
        let db = std::fs::read(p.selected.state_path()).unwrap();
        assert!(
            wal.len() + db.len() > 4096,
            "the record is somewhere in these files"
        );
    }

    /// STORE-128: a state that does not open is an error, and is left as it is.
    #[test]
    fn tsl_state_in_a_broken_state_db_is_an_error() {
        let p = with_keyring("tsl-broken");
        std::fs::write(p.selected.state_path(), [0x5a; 4096]).unwrap();
        let Err(error) = TslStateStore::open(&p.selected, "abc".into(), None, 0) else {
            panic!("a broken state.db must not open");
        };
        assert_eq!(error.kind(), "store_malformed");
        assert_eq!(
            std::fs::read(p.selected.state_path()).unwrap(),
            [0x5a; 4096]
        );
    }
}
