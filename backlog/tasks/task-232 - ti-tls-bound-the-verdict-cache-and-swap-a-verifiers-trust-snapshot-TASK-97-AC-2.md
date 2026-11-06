---
id: TASK-232
title: >-
  ti-tls: bound the verdict cache and swap a verifier's trust snapshot (TASK-97
  AC 2)
status: To Do
assignee: []
created_date: '2026-11-06T12:16:00Z'
updated_date: '2026-11-06T14:30:00Z'
labels:
  - ti-tls
  - security
dependencies: []
priority: medium
ordinal: 243000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-97 AC 2 asks for a bounded verdict cache over an atomically swapped trust snapshot. ti-tls's Verdicts is a Mutex<HashMap> without a bound: an accepted verdict leaves only when looked up after it expired, so a long-running host that meets many chains or names grows it without limit. TiVerifier holds one ServerCheck (one TrustStore) for its life; a server that reloads the TSL has to build a new verifier and ClientConfig. Bound the cache (size and eviction of expired entries on insert) and give the ti verifier a snapshot that can be replaced while connections use the old one, without a new dependency unless the maintainer agrees (arc-swap would be one).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 the verdict cache has a size bound and drops expired entries on insert, with a test
- [ ] #2 the ti verifier's trust snapshot can be replaced atomically while in use, with a test
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
TASK-98.2 review: the Go verifiers also stop reuse at the status's nextUpdate (TLSV-050) for ti and for CRL-based web verdicts; ti-tls's reusable_until does not. Align with the bound.
<!-- SECTION:NOTES:END -->
