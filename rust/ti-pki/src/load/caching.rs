//! [`CachingLoader`]: [`ti_cache::Cache`] applied to a trust-material [`Loader`].

use ti_cache::{
    Cache, CacheEntry, CacheLookupError, CachePolicy, CacheStore, Conditional, OriginResponse,
};

use super::artifact::Artifact;
use super::loader::{Fetched, LoadError, Loaded, Loader};
use super::maybe_send::{MaybeSend, MaybeSync};
use crate::time::Clock;

/// [`Cache`] over a [`Loader`]: the trust-material stack's caching layer.
#[derive(Debug)]
pub struct CachingLoader<L, S, C> {
    inner: L,
    cache: Cache<S, C>,
}

impl<L, S, C> CachingLoader<L, S, C>
where
    L: Loader + MaybeSend + MaybeSync,
    S: CacheStore + MaybeSend + MaybeSync,
    C: Clock + MaybeSend + MaybeSync,
{
    /// Caches `inner` in `store`.
    pub fn new(inner: L, store: S, clock: C, policy: CachePolicy) -> Self {
        CachingLoader {
            inner,
            cache: Cache::new(store, clock, policy),
        }
    }
}

impl<L, S, C> Loader for CachingLoader<L, S, C>
where
    L: Loader + MaybeSend + MaybeSync,
    S: CacheStore + MaybeSend + MaybeSync,
    C: Clock + MaybeSend + MaybeSync,
{
    async fn fetch(&self, artifact: Artifact, cond: Conditional<'_>) -> Result<Fetched, LoadError> {
        let key = self.inner.cache_key(artifact);
        let cached = self
            .cache
            .get(&key, async |validators| {
                Ok(match self.inner.fetch(artifact, validators).await? {
                    Fetched::Body(loaded) => OriginResponse::Body(CacheEntry {
                        body: loaded.body,
                        meta: loaded.meta,
                    }),
                    Fetched::NotModified(meta) => OriginResponse::NotModified(meta),
                })
            })
            .await
            .map_err(|error| match error {
                CacheLookupError::Store(e) => LoadError::Cache(e),
                CacheLookupError::OfflineMiss => LoadError::Offline(artifact),
                CacheLookupError::UnexpectedNotModified => {
                    LoadError::UnexpectedNotModified(artifact)
                }
                CacheLookupError::Origin(e) => e,
            })?;
        let loaded = Loaded {
            body: cached.body,
            meta: cached.meta,
            stale: cached.stale,
        };
        Ok(answer(loaded, cond))
    }

    fn cache_key(&self, artifact: Artifact) -> String {
        self.inner.cache_key(artifact)
    }
}

/// Answers the caller's own validators: "not modified" if its copy matches.
fn answer(loaded: Loaded, cond: Conditional<'_>) -> Fetched {
    match (cond.etag, loaded.meta.etag.as_deref()) {
        (Some(theirs), Some(ours)) if theirs == ours && loaded.stale.is_none() => {
            Fetched::NotModified(loaded.meta)
        }
        _ => Fetched::Body(loaded),
    }
}

#[cfg(test)]
mod tests {
    use core::time::Duration;

    use futures_lite::future::block_on;

    use super::*;
    use crate::TrustConfig;
    use crate::load::{
        ArtifactResponse, FixedClock, HttpLoader, MemoryCacheStore, Meta, MockTransport,
        ResponseMeta, Source, Timestamp, TransportError, TransportErrorKind,
    };

    const HOUR: Duration = Duration::from_hours(1);
    const T0: Timestamp = Timestamp(1_000_000);

    fn fresh(body: &[u8], etag: &str) -> ArtifactResponse {
        ArtifactResponse::Fresh {
            body: body.to_vec(),
            meta: ResponseMeta {
                etag: Some(etag.into()),
                last_modified: None,
                max_age: None,
                source: Source::Http,
            },
        }
    }

    fn not_modified(etag: &str) -> ArtifactResponse {
        ArtifactResponse::NotModified {
            meta: ResponseMeta {
                etag: Some(etag.into()),
                last_modified: None,
                max_age: None,
                source: Source::Http,
            },
        }
    }

    fn unreachable() -> Result<ArtifactResponse, TransportError> {
        Err(TransportError {
            kind: TransportErrorKind::Network,
            message: "connection refused".into(),
            retryable: true,
        })
    }

    fn policy(offline: bool) -> CachePolicy {
        CachePolicy {
            max_age: HOUR,
            stale_if_error: 5 * HOUR,
            offline,
        }
    }

    type Stack<'a> = CachingLoader<
        HttpLoader<&'a MockTransport, &'a FixedClock>,
        &'a MemoryCacheStore,
        &'a FixedClock,
    >;

    fn stack<'a>(
        transport: &'a MockTransport,
        store: &'a MemoryCacheStore,
        clock: &'a FixedClock,
        offline: bool,
    ) -> Stack<'a> {
        let http = HttpLoader::new(&TrustConfig::preset_prod(), transport, clock);
        CachingLoader::new(http, store, clock, policy(offline))
    }

    #[test]
    fn miss_then_hit_within_max_age() {
        let (transport, store, clock) = (
            MockTransport::new([Ok(fresh(b"roots-1", "e1"))]),
            MemoryCacheStore::new(),
            FixedClock::new(T0),
        );
        let loader = stack(&transport, &store, &clock, false);

        let first = block_on(loader.load(Artifact::Roots)).unwrap();
        assert_eq!(
            (first.body.as_slice(), first.meta.source),
            (&b"roots-1"[..], Source::Http)
        );

        clock.advance(HOUR / 2);
        let second = block_on(loader.load(Artifact::Roots)).unwrap();
        assert_eq!(
            (second.body.as_slice(), second.meta.source),
            (&b"roots-1"[..], Source::Cache)
        );
        assert_eq!(transport.requests().len(), 1);
    }

    #[test]
    fn revalidation_not_modified_moves_fetched_at() {
        let (transport, store, clock) = (
            MockTransport::new([Ok(fresh(b"roots-1", "e1")), Ok(not_modified("e1"))]),
            MemoryCacheStore::new(),
            FixedClock::new(T0),
        );
        let loader = stack(&transport, &store, &clock, false);
        block_on(loader.load(Artifact::Roots)).unwrap();

        clock.advance(2 * HOUR);
        let revalidated = block_on(loader.load(Artifact::Roots)).unwrap();
        assert_eq!(revalidated.body, b"roots-1");
        assert_eq!(revalidated.meta.fetched_at, T0 + 2 * HOUR);
        assert_eq!(transport.requests()[1].etag.as_deref(), Some("e1"));

        let key = loader.cache_key(Artifact::Roots);
        let entry = block_on(store.get(&key)).unwrap().unwrap();
        assert_eq!(entry.meta.fetched_at, T0 + 2 * HOUR);
    }

    #[test]
    fn offline_never_calls_the_inner_loader() {
        let (transport, store, clock) = (
            MockTransport::new([]),
            MemoryCacheStore::new(),
            FixedClock::new(T0),
        );
        let loader = stack(&transport, &store, &clock, true);
        assert_eq!(
            block_on(loader.load(Artifact::Roots)).unwrap_err(),
            LoadError::Offline(Artifact::Roots)
        );

        let key = loader.cache_key(Artifact::Roots);
        let meta = Meta {
            etag: None,
            last_modified: None,
            fetched_at: T0,
            max_age: None,
            source: Source::Bundle,
        };
        block_on(store.put(
            &key,
            &CacheEntry {
                body: b"roots".to_vec(),
                meta,
            },
        ))
        .unwrap();
        clock.advance(100 * HOUR);
        assert_eq!(
            block_on(loader.load(Artifact::Roots)).unwrap().body,
            b"roots"
        );
        assert!(transport.requests().is_empty());
    }

    #[test]
    fn stale_if_error_window_then_propagate() {
        let (transport, store, clock) = (
            MockTransport::new([Ok(fresh(b"roots-1", "e1")), unreachable(), unreachable()]),
            MemoryCacheStore::new(),
            FixedClock::new(T0),
        );
        let loader = stack(&transport, &store, &clock, false);
        block_on(loader.load(Artifact::Roots)).unwrap();

        clock.set(T0 + 5 * HOUR);
        let stale = block_on(loader.load(Artifact::Roots)).unwrap();
        assert_eq!(stale.body, b"roots-1");
        assert!(matches!(stale.stale, Some(LoadError::Transport(_))));

        clock.set(T0 + 6 * HOUR);
        assert!(matches!(
            block_on(loader.load(Artifact::Roots)),
            Err(LoadError::Transport(_))
        ));
    }

    #[test]
    fn http_loader_keys_by_url() {
        let (transport, clock) = (MockTransport::new([]), FixedClock::new(T0));
        let http = HttpLoader::new(&TrustConfig::preset_prod(), &transport, &clock);
        assert_eq!(
            http.cache_key(Artifact::Roots),
            Artifact::Roots.cache_key(crate::roots::URL_PROD)
        );
    }
}
