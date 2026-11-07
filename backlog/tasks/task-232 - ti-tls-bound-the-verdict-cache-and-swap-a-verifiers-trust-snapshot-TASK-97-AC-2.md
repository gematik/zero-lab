---
id: TASK-232
title: >-
  ti-tls: bound the verdict cache and swap a verifier's trust snapshot (TASK-97
  AC 2)
status: In Progress
assignee: []
created_date: '2026-11-06T12:16:00Z'
updated_date: '2026-11-07T08:54:00Z'
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
- [x] #1 the verdict cache has a size bound and drops expired entries on insert, with a test
- [x] #2 the ti verifier's trust snapshot can be replaced atomically while in use, with a test
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. Verdicts: a bound (4096 entries); every insert drops expired entries, and at the bound the entry that expires first. 2. TiVerifier: the ServerCheck and its verdict cache are one snapshot behind RwLock<Arc<_>>; replace() swaps both, so a handshake in flight keeps the old snapshot and no verdict outlives the material it was reached with (TLSV-050). The read lock is held only to clone the Arc; no new dependency (no arc-swap). 3. TLSV-050 nextUpdate: ti-pki's tls::Verdict gains status_next_update; ti and web (CRL via x509-cert, already a dependency) stop reuse at it, as the Go verifiers do. Branch task-232 in a worktree.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
TASK-98.2 review: the Go verifiers also stop reuse at the status's nextUpdate (TLSV-050) for ti and for CRL-based web verdicts; ti-tls's reusable_until does not. Align with the bound.

2026-11-07: done on branch task-232 (3d30052d). Verdicts keep at most 4096; each insert drops expired entries, at the bound the entry expiring first goes. TiVerifier::replace swaps check and verdicts as one Arc'd snapshot behind an RwLock held only to clone the Arc (no arc-swap); a handshake in flight finishes on its snapshot. ti-pki tls::Verdict gains status_next_update; ti and CRL-based web verdicts end at nextUpdate (TLSV-050), as in Go. Tests: tlsv_050_the_verdict_cache_is_bounded_and_drops_expired_verdicts, tlsv_050_nothing_without_reuse_left_is_kept, tlsv_050_a_ti_verdict_ends_at_its_status_next_update, tlsv_050_a_crl_verdict_ends_at_the_lists_next_update, tlsv_050_a_ti_verifiers_trust_material_is_replaced_in_use. tls-bench: ti cold 815us, cached 584ns.
<!-- SECTION:NOTES:END -->
