---
id: TASK-303
title: 'kv: an atomic counter'
status: To Do
assignee: []
created_date: '2026-11-12T21:31:00Z'
labels: []
dependencies: []
ordinal: 319000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
kv.Store can set, take and list, and cannot count: two replicas that read a number and write it back lose increments. A rate limit that holds across replicas needs one operation that adds to a count and returns the total, with an expiry set when the count starts, so that a count is a window of fixed length. Asked for by zeta-pdp-go (its TASK-46: leased quotas, a replica adds a block to the shared count and serves that many requests from memory).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 An optional interface of the stores adds n to a key atomically across replicas and returns the total; a count that is absent or expired starts from zero with the given TTL
- [ ] #2 Memory and Postgres stores implement it, the sealed store passes it through; concurrent adds lose nothing
<!-- AC:END -->
