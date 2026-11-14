---
id: TASK-309
title: >-
  dpop: Replays instead of ReplayCache, ctx and error on its interfaces;
  kv-backed Replays moves to the hosts
status: In Progress
assignee: []
created_date: '2026-11-14T10:42:00Z'
updated_date: '2026-11-14T11:01:00Z'
labels: []
dependencies: []
ordinal: 324000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
dpop.ReplayCache is not a cache: losing an entry before it expires lets a proof through twice. Rename it Replays (with MemoryReplayCache, NewMemoryReplayCache, ErrReplayCacheFull and pep's WithDPoPReplayCache after it), the same naming as Revocations (TASK-307).

Both dpop interfaces get a context and an error, so a stored or remote implementation can fail and the verifier denies: Replays.Seen(ctx, id, until) (bool, error) and NonceSource.Valid(ctx, nonce) (bool, error), Fresh(ctx) (string, error). The Verifier passes the request's context through. The cryptographic nonce.Source and the stored implementations both meet the new shape.

kv.ReplayCache (kv/replay.go) is dpop logic inside kv: the dpop:replay: prefix, the clock-skew minute, hashing the proof id, and a 5 s timeout invented because Seen has no context. Per the target pattern it moves to the hosts that wire it (cmd/zero-pdp, with TASK-306), on kv's generic SetIfAbsent; kv keeps nothing dpop-specific. Breaking change for dpop, nonce, kv, pep, pdp and zaddy, all in this repository.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 dpop exports Replays, MemoryReplays and their constructor; no ReplayCache name remains in dpop, pep, pdp or kv
- [ ] #2 Replays.Seen, NonceSource.Valid and NonceSource.Fresh take a context and return an error; an error refuses the proof, with a test per method
- [ ] #3 nonce.Source meets the new NonceSource
- [ ] #4 kv has no replay type; the kv-backed Replays lives with the wiring in the hosts
- [ ] #5 Release notes of dpop, nonce and kv name the breaking change
- [ ] #6 pep's builder refuses a missing Replays; zaddy passes in-memory Replays explicitly and logs that they hold for one replica
- [ ] #7 nonce.Record becomes nonce.Redemptions with Seen(ctx, id, until) (bool, error), true meaning already redeemed; one kv-backed type in zero-pdp serves both, with unchanged key layouts
<!-- AC:END -->
