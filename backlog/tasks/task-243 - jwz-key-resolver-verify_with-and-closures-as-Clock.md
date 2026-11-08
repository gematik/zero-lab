---
id: TASK-243
title: 'jwz: key resolver, verify_with and closures as Clock'
status: Done
assignee: []
created_date: '2026-11-07T15:52:00Z'
updated_date: '2026-11-08T17:37:00Z'
labels:
  - jwz
  - architecture
milestone: m-1
dependencies: []
references:
  - docs/principles.md
  - rust/jwz/docs/adr/0001-jwz.md
priority: medium
type: feature
ordinal: 259000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Decision-15: a JWS verifier gets its keys through a trait the host implements, not from a crate that fetches them. jwz already has this seam for x5c (ChainValidator, AsyncChainValidator); the same for JWK Sets replaces ti-jwks, whose fetching and caching move into ti-client (RemoteJwks). The key selection rules of RFC 7517 §4.2–4.4 are JWK rules and belong in jwz. Time enters every TI crate as a function (decision-15), so jwz's Clock should accept one too.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 jwz::jwk has KeyResolver and AsyncKeyResolver (the keys that may have signed a JWS with a given header and algorithm), and JwkSet implements KeyResolver
- [x] #2 JwkSet::signing_keys(kid, alg) selects by kid (all when none), use, key_ops and alg as RFC 7517 §4.2–4.4 say, with tests named after those sections
- [x] #3 Jws::verify_with and Jws::verify_with_async try each resolved key and fail with VerificationFailed when none verifies; a fetched key is never trusted for having been fetched
- [x] #4 every Fn() -> u64 implements jwt::Clock; SystemClock and FixedClock stay
- [x] #5 traceability table blessed; released in jwz 0.2.0 (TASK-272), not as 0.1.x: the release carries TASK-271's breaking change
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
KeyResolver::resolve and AsyncKeyResolver::resolve_async return candidate Jwks (owned, so an async resolver can hand them out); JwkSet implements both through JwkSet::signing_keys (kid per §4.5, use/key_ops per §4.2/4.3, alg per §4.4). Jws::verify_with(resolver, registry, &Arc<backend>) makes each candidate a SoftwareKey for the accepted algorithm, skips what does not fit, and fails VerificationFailed when none verifies. Every Fn() -> u64 is a Clock. Added ErrorCode::KeyUnavailable and a public Error::new so a host's resolver can report an unreachable origin (also serves ChainValidator). Rationale for resolvers, time as a function and the browser's fetch in docs/guide.md; ti-pki's README explains its loaders and time the same way. The jwz stamps are stale until TASK-272's single restamp.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
jwz::jwk::KeyResolver/AsyncKeyResolver; JwkSet::signing_keys by RFC 7517 §4.2-4.5; Jws::verify_with/verify_with_async try each resolved key and fail with VerificationFailed; any Fn() -> u64 is a Clock; ErrorCode::KeyUnavailable and a public Error::new. Rationale for resolvers, time as a function and the browser in jwz's guide and ti-pki's README. Released in jwz 0.2.0.
<!-- SECTION:FINAL_SUMMARY:END -->
