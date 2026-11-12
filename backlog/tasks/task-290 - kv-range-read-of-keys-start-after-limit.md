---
id: TASK-290
title: 'kv: range read of keys (start after, limit)'
status: To Do
assignee: []
created_date: '2026-11-12T18:11:00Z'
labels: []
dependencies: []
ordinal: 306000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
kv.Store can list keys by prefix only: Keys(ctx, prefix) returns every match, in one slice. A caller that needs "what is new since X" or wants to read a large set in pages has no way to ask for it. zeta-pdp-go reads session revocations since a time for the PEP's revocation stream; it works around the gap by putting the time in the key and listing decimal prefixes of it as time buckets (pdp/kvstore, its TASK-25), which bounds a reading but is not paging.

Wanted: a range read on Store, for example Keys with a start-after key and a limit (ordered by key, as the Postgres backend already orders), implemented by the memory, sealed and Postgres stores. The Postgres index on key should serve it (text_pattern_ops or a C collation for the prefix and range predicates).

Found by zeta-pdp-go.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Store offers an ordered read of keys below a prefix that starts after a given key and returns at most a given number
- [ ] #2 Memory, sealed and Postgres stores implement it; the Postgres query uses an index
- [ ] #3 Keys(prefix) is documented as unbounded
<!-- AC:END -->
