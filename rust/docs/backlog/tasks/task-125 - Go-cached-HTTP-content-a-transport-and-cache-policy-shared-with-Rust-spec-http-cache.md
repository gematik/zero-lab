---
id: TASK-125
title: >-
  Go: cached HTTP content, a transport and cache policy shared with Rust
  (spec/http-cache)
status: To Do
assignee: []
created_date: '2026-10-21 07:14'
updated_date: '2026-10-21 07:17'
labels:
  - go
  - rust
  - spec
  - store
dependencies: []
priority: high
ordinal: 136000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Fetching a document over HTTP and keeping it is a common need: JWKS, OIDC and OAuth discovery, OpenID Federation entity statements, the TSL and roots in Rust. Rust has it as ti-pki's load::Transport (the host owns the HTTP client; get with validators, post) and ti_store::Cache over a CacheStore (Meta: etag, last_modified, fetched_at, max_age; fresh within max_age, revalidated with If-None-Match / If-Modified-Since, stale_if_error when the origin fails). spec/store leaves the cache policy out ('it sits above the store'), so Go would grow a second, drifting policy on the same cache.db. Write the policy down as spec/http-cache (freshness from Cache-Control max-age capped by a configured maximum, validators and 304, stale-if-error window, fetched_at never in the future, body size limit, keys and record layout in cache.db, what is never cached: tokens, error responses) with shared test vectors; implement it in Go on the standard library (a Transport interface over net/http, a CacheStore over go/store's cache.db namespace and memory, the Cache policy); check ti_store::Cache against the same vectors. Related: TASK-64 (one HTTP vocabulary in Rust), TASK-105 (tokens and .well-known in the store), TASK-75 (SSRF review of outbound fetches).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 spec/http-cache states the policy with requirement IDs and test vectors; ti_store::Cache passes the vectors or the differences are filed
- [ ] #2 a Go package, standard library only, offers Transport, CacheStore (go/store cache.db and memory) and Cache with the spec's policy, tested by the same vectors
- [ ] #3 Go and Rust read each other's cache.db entries for the same URL
- [ ] #4 spec/http-cache states the retry policy (which failures, attempts, backoff with jitter, Retry-After cap, overall deadline, per-origin rest after repeated failures) with vectors; Go implements it and ti-pki's retry and rest behaviour is checked against it or the differences filed
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Retries (maintainer, 2026-10-21) belong to the same building block and the same spec: a GET is retried on a transport failure (connect, timeout, reset), 429 and 502/503/504, never on another 4xx or after a body was accepted; a bounded number of attempts with exponential backoff and full jitter inside an overall deadline the caller sets; Retry-After honoured up to a cap; per origin, a breaker that rests the origin after repeated failures (as ti-pki's OcspChecker does for a responder) and serves stale-if-error meanwhile; POST is not retried unless the caller marks it idempotent. Retries and the breaker are observable (attempt count, resting until).
<!-- SECTION:NOTES:END -->
