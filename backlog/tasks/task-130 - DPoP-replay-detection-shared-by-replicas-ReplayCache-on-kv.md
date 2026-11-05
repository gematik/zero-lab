---
id: TASK-130
title: DPoP replay detection shared by replicas (ReplayCache on kv)
status: Done
assignee: []
created_date: 2026-10-21 07:53
updated_date: '2026-11-05T19:25:00Z'
labels:
  - go
  - kv
  - security
dependencies: []
priority: medium
ordinal: 141000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
go/dpop's MemoryReplayCache detects a replayed proof only at the replica that saw it first (RFC 9449 Section 11.1: 'it may not always be feasible ... when multiple servers behind a single endpoint have no shared state'). pdp and pep run replicated on kv. A ReplayCache on kv needs an atomic set-if-absent with TTL, which kv.Store lacks (Set overwrites, Take consumes). Add SetIfAbsent (memory, Postgres: INSERT ... ON CONFLICT DO NOTHING with the database clock, TASK-107) and a kv-backed ReplayCache, and wire it into pdp and pep.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 kv.Store offers an atomic set-if-absent with TTL in every backend, tested under concurrency
- [ ] #2 pdp and pep use a kv-backed ReplayCache; a proof replayed at another replica is refused (test with two servers on one store)
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
kv.ReplayCache is wired into pdp. pep's Builder takes one, but its only production user is zaddy, which has no kv, and pep/proxy verifies no DPoP proofs. So AC 2 stays open for zaddy.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Closed: pdp uses the kv-backed ReplayCache, so a proof replayed at another replica is refused. zaddy has no kv store, so its pep keeps the memory cache.
<!-- SECTION:FINAL_SUMMARY:END -->
