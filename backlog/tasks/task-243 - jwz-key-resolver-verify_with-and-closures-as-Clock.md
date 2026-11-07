---
id: TASK-243
title: 'jwz: key resolver, verify_with and closures as Clock'
status: To Do
assignee: []
created_date: '2026-11-07T15:52:00Z'
labels:
  - jwz
  - architecture
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
- [ ] #1 jwz::jwk has KeyResolver and AsyncKeyResolver (the keys that may have signed a JWS with a given header and algorithm), and JwkSet implements KeyResolver
- [ ] #2 JwkSet::signing_keys(kid, alg) selects by kid (all when none), use, key_ops and alg as RFC 7517 §4.2–4.4 say, with tests named after those sections
- [ ] #3 Jws::verify_with and Jws::verify_with_async try each resolved key and fail with VerificationFailed when none verifies; a fetched key is never trusted for having been fetched
- [ ] #4 every Fn() -> u64 implements jwt::Clock; SystemClock and FixedClock stay
- [ ] #5 traceability table blessed, mutation score recorded, released as a 0.1.x minor version
<!-- AC:END -->
