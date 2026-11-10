# ti-cache

HTTP-style caching for gematik Telematikinfrastruktur (TI) clients: whatever a client
downloads (roots.json, the TSL, a Konnektor's service directory, a JWK Set) goes through one
`Cache`, which
- serves an entry without asking the origin while it is younger than `max_age`;
- then revalidates it with its `ETag`/`Last-Modified`, so an unchanged body is not
  downloaded again;
- keeps serving the stored copy for `stale_if_error` when the origin fails, and says so;
- in offline mode never asks the origin at all;
- with `origin_freshness`, lets the origin's `Cache-Control` decide how long an entry is
  fresh, within a floor and a cap (`CacheControl` reads the field, RFC 9111 §5.2);
- with `force`, refreshes an entry on a caller's suspicion (a JWK Set without the key a
  token names), at most once per `min_forced_interval`.

The store is a dumb key/value trait (`CacheStore`); the semantics live in `Cache`, so a
store is trivial to back with memory, files, Redis or a browser API. The origin is a
closure per call, so one cache serves any kind of artefact.

```rust
use ti_cache::{Cache, CacheEntry, CachePolicy, MemoryCacheStore, Meta, OriginResponse, Source};
use ti_types::Timestamp;

# futures_lite::future::block_on(async {
let cache = Cache::new(
    MemoryCacheStore::new(),
    || Timestamp(1_700_000_000),
    CachePolicy::default(),
);
let sds = cache
    .get("example/v1/sds", async |_validators| {
        Ok::<_, std::io::Error>(OriginResponse::Body(CacheEntry {
            body: b"<ConnectorServices/>".to_vec(),
            meta: Meta::new(cache.now(), Source::Http),
        }))
    })
    .await?;
assert_eq!(sds.meta.source, Source::Http);
# Ok::<(), ti_cache::CacheLookupError<std::io::Error>>(())
# }).unwrap();
```

The cache is as untrusted as the network: callers verify what it returns exactly as
they verify a download.

Traits carry no `Send` bounds and the crate has no I/O, so it builds for
`wasm32-unknown-unknown`.

## License

EUPL-1.2. Copyright, licence and gematik's notes: [repository README](https://github.com/gematik/zero-lab#license).
