---
id: TASK-18
title: 'jwz: JWK Set fetch adapters'
status: Done
assignee: []
created_date: 2026-10-10 05:58
updated_date: '2026-11-06T07:28:00Z'
labels:
  - jwz
dependencies: []
priority: high
ordinal: 5000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
jwz parses JWK Sets but never fetches: the caller brings the keys. Adapters for jwks_uri with caching and rotation (kid miss triggers one refetch), over ureq, reqwest and browser fetch, as crates or features outside jwz's core.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Fetch, cache with max-age, refetch once on unknown kid, rate-limited
- [x] #2 No network code in jwz itself; jwz-backends still passes
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
f48dddef ti-cache: CacheControl (fuzz target, just fuzz-ti-cache: 2.8M runs clean), CachePolicy::origin_freshness + FreshnessBounds (off by default), Cache::force with min_forced_interval. 6e018c0f ti-jwks: JwksSource::keys(kid, alg), policy(), Limits, http::Transport, ureq feature; 12 tests incl. loopback; core-deps, unsafe-free, wasm32. Mutation threshold 0.8 added for ti-jwks as a security crate.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
ti-cache reads Cache-Control (fuzzed), lets the origin's lifetime count within bounds (opt-in) and rate-limits forced refreshes; new crate ti-jwks: JwksSource::keys(kid, alg) on ti-cache with the maintainer's defaults, https only, redirects refused, body and key caps, Transport trait and ureq adapter. jwz has no network code; jwz-backends passes.
<!-- SECTION:FINAL_SUMMARY:END -->
