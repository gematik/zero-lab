---
id: TASK-121
title: 'pki inspect: unknown issuer on fresh install until the TSL is cached'
status: To Do
assignee: []
created_date: '2026-10-14 07:25'
labels:
  - ti-cli
  - bug
dependencies: []
references:
  - ti-cli/src/commands/inspect.rs
  - ti-cli/src/commands/mod.rs
priority: medium
ordinal: 42000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
On a fresh install, `ti pki inspect` of a RU (ref) end-entity certificate (e.g. C.HCI.AUT from GEM.SMCB-CA57 TEST-ONLY) shows the trust tree ending in "? GEM.SMCB-CA57 TEST-ONLY — issuer not among the trusted CAs". `ti pki verify` of the same file validates it (VALID, chain up to GEM.RCA8 TEST-ONLY via the TSL). Running `inspect` again afterwards shows the complete tree.

Cause: `inspect` builds its "Trust (not validated)" tree from the cache and embedded roots only, never the network (inspect.rs `trees`, Session::new(global, true, …)). With no TSL cached yet, the store holds only the roots and none of the TSL CAs, so the issuing CA is missing. `verify` fetches the TSL and caches it, which is why the second `inspect` works.

The result is misleading: the CA is trusted, the trust material is just not loaded yet. Either load the TSL on first use (respecting offline/airgap mode) or say that the TSL is not cached and how to get it, instead of "issuer not among the trusted CAs".
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 on a fresh install (empty cache), inspect of a ref certificate issued by a TSL CA does not claim the issuer is untrusted
- [ ] #2 when the TSL is not available (offline / airgap without cache), the tree says the TSL is not loaded and points to the command that fetches it
- [ ] #3 a test with an empty cache covers the inspect trust tree
<!-- AC:END -->
