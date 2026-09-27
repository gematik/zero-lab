//! [`Cache`]: HTTP-style caching of named bodies in any [`CacheStore`].

use core::time::Duration;

use ti_types::Clock;

use crate::store::{CacheEntry, CacheError, CacheStore, Meta, Source};

/// How [`Cache`] uses its store.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CachePolicy {
    /// Serve from the store without asking the origin while an entry is younger than this.
    pub max_age: Duration,
    /// When the origin fails, keep serving an entry for this long past `max_age`.
    pub stale_if_error: Duration,
    /// Never contact the origin; serve whatever the store holds, however old. For
    /// air-gapped setups with a pre-populated store; callers age entries out by their
    /// own freshness rules.
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

/// Validators for a conditional request to the origin.
#[derive(Clone, Copy, Debug, Default)]
pub struct Conditional<'a> {
    /// The `ETag` of the copy the caller holds.
    pub etag: Option<&'a str>,
    /// The `Last-Modified` of the copy the caller holds.
    pub last_modified: Option<&'a str>,
}

impl<'a> Conditional<'a> {
    /// No validators: always answer with a body.
    pub const NONE: Conditional<'static> = Conditional {
        etag: None,
        last_modified: None,
    };

    /// The validators of `meta`.
    pub fn from_meta(meta: &'a Meta) -> Self {
        Conditional {
            etag: meta.etag.as_deref(),
            last_modified: meta.last_modified.as_deref(),
        }
    }
}

/// What the origin answers to [`Cache::get`].
#[derive(Clone, Debug)]
pub enum OriginResponse {
    /// A new body.
    Body(CacheEntry),
    /// The validators matched: the stored copy is current as of this metadata.
    NotModified(Meta),
}

/// A body served by [`Cache::get`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cached<E> {
    /// The bytes.
    pub body: Vec<u8>,
    /// Their metadata; [`Source::Cache`] when they came from the store.
    pub meta: Meta,
    /// Set when the body is a stale copy: the origin's error.
    pub stale: Option<E>,
}

/// Why [`Cache::get`] has no body. Deliberately exhaustive: callers map every case
/// onto their own error type, and these are all the ways a lookup can fail.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CacheLookupError<E> {
    /// The store failed.
    #[error(transparent)]
    Store(CacheError),
    /// Offline and nothing stored under the key.
    #[error("offline and nothing cached")]
    OfflineMiss,
    /// The origin answered "not modified" although nothing was stored to compare.
    #[error("unexpected not-modified")]
    UnexpectedNotModified,
    /// The origin failed and no usable copy was stored.
    #[error(transparent)]
    Origin(E),
}

/// Serves fresh entries from `store`, revalidates older ones with the stored
/// validators, and falls back to the stored copy for `stale_if_error` when the origin
/// fails. Keyed by string, so any crate can cache any artefact with the same policy;
/// the origin is a closure per call.
#[derive(Debug)]
pub struct Cache<S, C> {
    store: S,
    clock: C,
    policy: CachePolicy,
}

impl<S: CacheStore, C: Clock> Cache<S, C> {
    /// A cache over `store`.
    pub fn new(store: S, clock: C, policy: CachePolicy) -> Self {
        Cache {
            store,
            clock,
            policy,
        }
    }

    /// The clock the cache ages entries by; origins stamp `fetched_at` with it.
    pub fn clock(&self) -> &C {
        &self.clock
    }

    /// The body under `key`: from the store while fresh (or offline), otherwise from
    /// `origin`, which receives the stored copy's validators and may answer "not
    /// modified". A failing origin is answered with the stored copy while it is within
    /// `stale_if_error`.
    ///
    /// # Errors
    ///
    /// [`CacheLookupError`] when no body can be served.
    pub async fn get<E>(
        &self,
        key: &str,
        origin: impl AsyncFnOnce(Conditional<'_>) -> Result<OriginResponse, E>,
    ) -> Result<Cached<E>, CacheLookupError<E>> {
        let cached = self.store.get(key).await.map_err(CacheLookupError::Store)?;
        let now = self.clock.now();
        if let Some(entry) = &cached {
            let age = now.since(entry.meta.fetched_at);
            if age < self.policy.max_age || self.policy.offline {
                return Ok(stored(entry.clone(), None));
            }
        } else if self.policy.offline {
            return Err(CacheLookupError::OfflineMiss);
        }

        let validators = cached.as_ref().map_or(Conditional::NONE, |entry| {
            Conditional::from_meta(&entry.meta)
        });
        match origin(validators).await {
            Ok(OriginResponse::Body(entry)) => {
                self.store
                    .put(key, &entry)
                    .await
                    .map_err(CacheLookupError::Store)?;
                Ok(Cached {
                    body: entry.body,
                    meta: entry.meta,
                    stale: None,
                })
            }
            Ok(OriginResponse::NotModified(meta)) => {
                let Some(mut entry) = cached else {
                    return Err(CacheLookupError::UnexpectedNotModified);
                };
                entry.meta.fetched_at = meta.fetched_at;
                entry.meta.max_age = meta.max_age.or(entry.meta.max_age);
                self.store
                    .put(key, &entry)
                    .await
                    .map_err(CacheLookupError::Store)?;
                Ok(stored(entry, None))
            }
            Err(error) => match cached {
                Some(entry)
                    if now.since(entry.meta.fetched_at)
                        < self.policy.max_age + self.policy.stale_if_error =>
                {
                    Ok(stored(entry, Some(error)))
                }
                _ => Err(CacheLookupError::Origin(error)),
            },
        }
    }
}

fn stored<E>(entry: CacheEntry, stale: Option<E>) -> Cached<E> {
    Cached {
        body: entry.body,
        meta: Meta {
            source: Source::Cache,
            ..entry.meta
        },
        stale,
    }
}

#[cfg(test)]
mod tests {
    use core::cell::Cell;

    use futures_lite::future::block_on;
    use ti_types::Timestamp;

    use super::*;
    use crate::MemoryCacheStore;

    const HOUR: Duration = Duration::from_hours(1);
    const T0: Timestamp = Timestamp(1_000_000);

    struct TestClock(Cell<Timestamp>);

    impl Clock for TestClock {
        fn now(&self) -> Timestamp {
            self.0.get()
        }
    }

    impl TestClock {
        fn advance(&self, by: Duration) {
            self.0.set(self.0.get() + by);
        }
    }

    fn policy(offline: bool) -> CachePolicy {
        CachePolicy {
            max_age: HOUR,
            stale_if_error: 5 * HOUR,
            offline,
        }
    }

    /// An origin that counts its calls and answers from a script.
    fn origin<'a>(
        calls: &'a Cell<u32>,
        answer: Result<OriginResponse, &'static str>,
        clock: &'a TestClock,
    ) -> impl AsyncFnOnce(Conditional<'_>) -> Result<OriginResponse, &'static str> + 'a {
        async move |validators: Conditional<'_>| {
            calls.set(calls.get() + 1);
            match answer {
                Ok(OriginResponse::NotModified(_)) => {
                    assert_eq!(
                        validators.etag,
                        Some("\"v1\""),
                        "revalidates with the stored ETag"
                    );
                    Ok(OriginResponse::NotModified(meta(clock.now())))
                }
                other => other,
            }
        }
    }

    fn meta(at: Timestamp) -> Meta {
        Meta {
            etag: Some("\"v1\"".into()),
            ..Meta::new(at, Source::Http)
        }
    }

    fn body(at: Timestamp) -> OriginResponse {
        OriginResponse::Body(CacheEntry {
            body: b"sds".to_vec(),
            meta: meta(at),
        })
    }

    #[test]
    fn serves_revalidates_and_falls_back() {
        let (store, clock, calls) = (
            MemoryCacheStore::new(),
            TestClock(Cell::new(T0)),
            Cell::new(0),
        );
        let cache = Cache::new(&store, &clock, policy(false));
        let key = "ti-connector/v1/sds/abc";

        let first = block_on(cache.get(key, origin(&calls, Ok(body(T0)), &clock))).unwrap();
        assert_eq!(
            (first.body.as_slice(), first.meta.source),
            (&b"sds"[..], Source::Http)
        );
        let hit = block_on(cache.get(key, origin(&calls, Err("unused"), &clock))).unwrap();
        assert_eq!(
            (calls.get(), hit.meta.source),
            (1, Source::Cache),
            "fresh: no origin call"
        );

        clock.advance(2 * HOUR);
        let revalidated = block_on(cache.get(
            key,
            origin(&calls, Ok(OriginResponse::NotModified(meta(T0))), &clock),
        ))
        .unwrap();
        assert_eq!(
            revalidated.meta.fetched_at,
            clock.now(),
            "304 moves fetched_at"
        );
        assert_eq!(
            block_on(store.get(key)).unwrap().unwrap().meta.fetched_at,
            clock.now(),
            "and stores it"
        );
        assert_eq!(calls.get(), 2);

        clock.advance(2 * HOUR);
        let stale = block_on(cache.get(key, origin(&calls, Err("down"), &clock))).unwrap();
        assert_eq!(
            (stale.body.as_slice(), stale.stale),
            (&b"sds"[..], Some("down"))
        );
        clock.advance(10 * HOUR);
        assert_eq!(
            block_on(cache.get(key, origin(&calls, Err("down"), &clock))),
            Err(CacheLookupError::Origin("down")),
            "past stale_if_error the origin's error is returned"
        );
    }

    #[test]
    fn offline_never_asks_the_origin() {
        let (store, clock, calls) = (
            MemoryCacheStore::new(),
            TestClock(Cell::new(T0)),
            Cell::new(0),
        );
        let offline = Cache::new(&store, &clock, policy(true));
        assert_eq!(
            block_on(offline.get("k", origin(&calls, Ok(body(T0)), &clock))),
            Err(CacheLookupError::OfflineMiss)
        );
        assert_eq!(calls.get(), 0);
        let online = Cache::new(&store, &clock, policy(false));
        block_on(online.get("k", origin(&calls, Ok(body(T0)), &clock))).unwrap();
        clock.advance(100 * HOUR);
        let old = block_on(offline.get("k", origin(&calls, Err("unused"), &clock))).unwrap();
        assert_eq!((old.meta.source, calls.get()), (Source::Cache, 1));
    }

    #[test]
    fn not_modified_without_a_stored_copy_is_an_error() {
        let (store, clock) = (MemoryCacheStore::new(), TestClock(Cell::new(T0)));
        let cache = Cache::new(&store, &clock, policy(false));
        let answer =
            async |_: Conditional<'_>| Ok::<_, &str>(OriginResponse::NotModified(meta(T0)));
        assert_eq!(
            block_on(cache.get("k", answer)),
            Err(CacheLookupError::UnexpectedNotModified)
        );
    }
}
