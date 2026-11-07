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

//! What an operation uses after a load: the set read back from the cache and checked to
//! be the list the load verified, and the loader of a validation at another time.

use super::artifact::{Artifact, ArtifactRequest, ArtifactResponse, TrustMaterial};
use super::caching::CachingLoader;
use super::http::HttpLoader;
use super::loader::{Fetched, LoadError, Loader};
use super::maybe_send::{MaybeSend, MaybeSync};
use super::transport::{PostRequest, Transport, TransportError, TransportErrorKind};
use crate::TrustConfig;
use crate::time::Timestamp;
use ti_cache::{CachePolicy, CacheStore, Conditional};

/// A loader for a validation at another time than now: the published signer status is
/// left out, since it says nothing about that time (`spec/tsl-detached` TSLDET-023). At
/// the current time it is the inner loader.
#[derive(Debug)]
pub struct AtTime<L> {
    inner: L,
    past: bool,
}

impl<L: Loader + MaybeSend + MaybeSync> AtTime<L> {
    /// `inner` for a validation at `at`; `None` is now.
    pub fn new(inner: L, at: Option<Timestamp>) -> Self {
        AtTime {
            inner,
            past: at.is_some(),
        }
    }
}

impl<L: Loader + MaybeSend + MaybeSync> Loader for AtTime<L> {
    async fn fetch(&self, artifact: Artifact, cond: Conditional<'_>) -> Result<Fetched, LoadError> {
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

/// The transport of a run that makes no request: every request fails, so nothing leaves
/// the machine even where a component would otherwise ask the network.
#[derive(Clone, Copy, Debug, Default)]
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

/// `config`'s set as a load through `store` left it, read back without asking the origin,
/// even for a stale entry: the rollback check (TSLSIG-053) saw only what the load loaded.
/// The age rules are the load's: `offline`, any age is served; online, an entry past its
/// age is stale, which keeps a stale signer status out (TSLDET-015).
///
/// # Errors
///
/// [`LoadError::Offline`] offline with nothing cached; [`LoadError::Transport`] online when
/// an entry is gone; any other [`LoadError`] of the store.
pub async fn read_back<S, N>(
    config: &TrustConfig,
    store: S,
    now: N,
    offline: bool,
) -> Result<TrustMaterial, LoadError>
where
    S: CacheStore + MaybeSend + MaybeSync,
    N: Fn() -> Timestamp + Copy + MaybeSend + MaybeSync,
{
    CachingLoader::new(
        HttpLoader::new(config, NoNetwork, now),
        store,
        now,
        CachePolicy {
            offline,
            ..CachePolicy::default()
        },
    )
    .load_all()
    .await
}

/// Why a set read back is not the list a load verified.
#[cfg(feature = "brainpool")]
#[derive(Debug)]
pub enum ReadBackError {
    /// The list came without its detached signature.
    Unsigned,
    /// The list does not verify.
    Tsl(crate::tsl_signature::TslError),
    /// The list verifies but is another one than the load verified: another process
    /// replaced it.
    Replaced {
        /// The list read back.
        cached: crate::tsl_signature::TslState,
    },
}

/// `set`, read back after a load that verified the list `loaded`, verified again at `at`
/// or `now` and checked to be that very list: a list verified here alone, without the
/// rollback check of the load, could be an older one (TSLSIG-053). At another time than
/// now the published signer status is left out (TSLDET-023).
///
/// # Errors
///
/// [`ReadBackError`]: no signature, a list that does not verify, or another list.
#[cfg(feature = "brainpool")]
pub fn verify_read_back(
    mut set: TrustMaterial,
    config: &TrustConfig,
    loaded: &crate::tsl_signature::TslState,
    at: Option<Timestamp>,
    now: Timestamp,
) -> Result<(TrustMaterial, crate::tsl_signature::VerifiedTsl), ReadBackError> {
    use crate::tsl::Tsl;
    use crate::tsl_signature::{DetachedTsl, Sequence, TslState};

    if at.is_some()
        && let Some(detached) = &mut set.detached
    {
        detached.signer_status = None;
    }
    let detached = set.detached.as_ref().ok_or(ReadBackError::Unsigned)?;
    let files = DetachedTsl {
        signature: &detached.signature,
        signer_status: detached
            .signer_status
            .as_ref()
            .map(|(body, _)| body.as_slice()),
    };
    let verified = Tsl::parse_verified_with_status(&set.tsl, files, config, at.unwrap_or(now))
        .map_err(ReadBackError::Tsl)?;
    if !matches!(verified.check_sequence(Some(loaded)), Ok(Sequence::Same)) {
        return Err(ReadBackError::Replaced {
            cached: TslState::of(&verified.tsl),
        });
    }
    Ok((set, verified))
}

#[cfg(test)]
mod tests {
    use core::time::Duration;

    use futures_lite::future::block_on;
    use ti_cache::{CacheEntry, MemoryCacheStore, Meta, Source};

    use super::*;

    /// A loader that answers every artefact with its name, and counts the requests.
    #[derive(Default)]
    struct Named {
        asked: std::sync::Mutex<Vec<Artifact>>,
    }

    impl Loader for Named {
        async fn fetch(
            &self,
            artifact: Artifact,
            _: Conditional<'_>,
        ) -> Result<Fetched, LoadError> {
            self.asked.lock().unwrap().push(artifact);
            Err(LoadError::Unavailable(artifact))
        }
    }

    /// TSLDET-023: at another time the published status is not even asked for; at the
    /// current time it is.
    #[test]
    fn tsldet_023_a_loader_at_another_time_never_asks_for_the_signer_status() {
        let past = AtTime::new(Named::default(), Some(Timestamp(1)));
        let _ = block_on(past.fetch(Artifact::TslSignerStatus, Conditional::NONE));
        let _ = block_on(past.fetch(Artifact::TslSignature, Conditional::NONE));
        assert_eq!(
            *past.inner.asked.lock().unwrap(),
            [Artifact::TslSignature],
            "the status stays out"
        );

        let now = AtTime::new(Named::default(), None);
        let _ = block_on(now.fetch(Artifact::TslSignerStatus, Conditional::NONE));
        assert_eq!(
            *now.inner.asked.lock().unwrap(),
            [Artifact::TslSignerStatus]
        );
    }

    const T0: Timestamp = Timestamp(1_800_000_000);

    /// Puts `body` in `store` as `artifact` of the production preset, fetched `age` ago.
    fn cache(store: &MemoryCacheStore, artifact: Artifact, body: &[u8], age: Duration) {
        let key =
            HttpLoader::new(&TrustConfig::preset_prod(), NoNetwork, || T0).cache_key(artifact);
        let entry = CacheEntry {
            body: body.to_vec(),
            meta: Meta::new(T0 - age, Source::Http),
        };
        block_on(store.put(&key, &entry)).unwrap();
    }

    fn cached_set(store: &MemoryCacheStore, offline: bool) -> TrustMaterial {
        block_on(read_back(
            &TrustConfig::preset_prod(),
            store,
            || T0,
            offline,
        ))
        .unwrap()
    }

    /// TSLDET-015: online, a status past its age is what the load dropped, and the set
    /// read back must not bring it back; offline every age is served, as the load did.
    #[test]
    fn tsldet_015_a_stale_status_stays_out_of_the_set_read_back_online() {
        let store = MemoryCacheStore::default();
        let limit = CachePolicy::default().max_age;
        for artifact in [Artifact::Roots, Artifact::Tsl, Artifact::TslSignature] {
            cache(&store, artifact, b"body", limit * 2);
        }
        cache(&store, Artifact::TslSignerStatus, b"a status", limit);
        let status = |set: TrustMaterial| set.detached.and_then(|d| d.signer_status);
        assert!(status(cached_set(&store, false)).is_none(), "at the limit");
        assert!(status(cached_set(&store, true)).is_some(), "offline");

        cache(&store, Artifact::TslSignerStatus, b"a status", limit / 2);
        assert!(
            status(cached_set(&store, false)).is_some(),
            "under the limit it is what the load used"
        );
    }

    /// TSLSIG-053: the read back never reaches the origin, whatever the age of the entry.
    #[test]
    fn tslsig_053_the_set_is_read_back_without_the_network() {
        let store = MemoryCacheStore::default();
        let Err(LoadError::Transport(error)) =
            block_on(read_back(&TrustConfig::preset_prod(), &store, || T0, false))
        else {
            panic!("nothing is cached, and the origin is not asked");
        };
        assert!(
            error.message.starts_with("offline: not requesting"),
            "{error:?}"
        );
    }

    #[cfg(feature = "brainpool")]
    mod verified {
        use super::*;
        use crate::tsl_signature::TslState;

        const SET: &str = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../spec/tsl-detached/testdata/prod/ECC-RSA_TSL."
        );

        fn captured_at() -> Timestamp {
            Timestamp::parse_rfc3339("2026-11-01T16:47:42Z").unwrap()
        }

        fn set(status: Option<&[u8]>) -> TrustMaterial {
            let read = |suffix: &str| std::fs::read(format!("{SET}{suffix}")).unwrap();
            let meta = Meta::new(captured_at(), Source::Cache);
            TrustMaterial::new(Vec::new(), meta.clone(), read("xml"), meta.clone()).with_detached(
                Some(crate::load::Detached {
                    signature: read("sig"),
                    signature_meta: meta.clone(),
                    signer_status: status.map(|s| (s.to_vec(), meta.clone())),
                }),
            )
        }

        /// The state of the fixture's list.
        fn fixture_state() -> TslState {
            let xml = std::fs::read(format!("{SET}xml")).unwrap();
            TslState::of(&crate::tsl::Tsl::parse(&xml).unwrap())
        }

        /// TSLSIG-053: a list in the cache that is not the one the load verified, here one
        /// older than it, never reaches the caller, even though its signature is good.
        #[test]
        fn tslsig_053_a_list_read_back_other_than_the_verified_one_is_refused() {
            let cached = fixture_state();
            let newer = TslState {
                id: "ID-newer".into(),
                sequence_number: cached.sequence_number + 1,
            };
            let Err(ReadBackError::Replaced { cached: found }) = verify_read_back(
                set(None),
                &TrustConfig::preset_prod(),
                &newer,
                Some(captured_at()),
                captured_at(),
            ) else {
                panic!("another list than the verified one");
            };
            assert_eq!(found, cached);
            let (_, verified) = verify_read_back(
                set(None),
                &TrustConfig::preset_prod(),
                &cached,
                Some(captured_at()),
                captured_at(),
            )
            .expect("the list the load verified");
            assert_eq!(TslState::of(&verified.tsl), cached);
        }

        /// TSLDET-023: the published status says nothing about another time, so the set
        /// read back for one has none, however it was cached.
        #[test]
        fn tsldet_023_the_set_read_back_for_another_time_has_no_signer_status() {
            let loaded = fixture_state();
            let (set, verified) = verify_read_back(
                set(Some(b"a status")),
                &TrustConfig::preset_prod(),
                &loaded,
                Some(captured_at()),
                captured_at(),
            )
            .expect("garbage in the status is not read at another time");
            assert!(set.detached.unwrap().signer_status.is_none());
            assert!(verified.signer_status.is_none());
        }

        #[test]
        fn a_set_without_its_signature_is_refused() {
            let mut unsigned = set(None);
            unsigned.detached = None;
            assert!(matches!(
                verify_read_back(
                    unsigned,
                    &TrustConfig::preset_prod(),
                    &TslState {
                        id: String::new(),
                        sequence_number: 0
                    },
                    None,
                    captured_at(),
                ),
                Err(ReadBackError::Unsigned)
            ));
        }
    }
}
