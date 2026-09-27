# Changelog

## [Unreleased]

- `Cache`: freshness, revalidation, offline and stale-on-error over any `CacheStore`,
  keyed by string, with the origin passed per call (moved from ti-pki's
  `CachingLoader`). `CacheStore`, `CacheEntry`, `Meta`, `Source`, `CachePolicy`,
  `Conditional`, `OriginResponse`, `Cached`, `CacheLookupError`, `MemoryCacheStore`.
