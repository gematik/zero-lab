---
id: TASK-290
title: >-
  zeta-pdp-go: revocations since a time through a revocation store of its own,
  not a kv range read
status: To Do
assignee: []
created_date: '2026-11-12T18:11:00Z'
updated_date: '2026-11-14T10:36:00Z'
labels: []
dependencies: []
ordinal: 306000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
zeta-pdp-go reads session revocations since a time for the PEP's revocation stream. It works around kv.Store, which lists keys by prefix only, by putting the time in the key and listing decimal prefixes of it as time buckets (pdp/kvstore, its TASK-25). The first request was a range read (start after, limit) on kv.Store.

Decision: kv stays a generic key/value store and gets no query shaped by one caller. Per the target pattern, a module defines its store in its own terms and the host wires the backend: zeta-pdp-go defines a revocation store (revoke, revocations since a time), and its command wires an implementation; a Postgres one can keep revocations in their own table with an indexed time column instead of encoding time in keys. The in-repo counterpart is pep/proxy's Revocations (TASK-307).

Found by zeta-pdp-go.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 kv.Store gets no range read for this; Keys(prefix) is documented as unbounded
- [ ] #2 zeta-pdp-go has a revocation store interface with a since-time read, wired by its host
- [ ] #3 Its Postgres implementation answers since-time with an index, not time buckets in keys
<!-- AC:END -->
