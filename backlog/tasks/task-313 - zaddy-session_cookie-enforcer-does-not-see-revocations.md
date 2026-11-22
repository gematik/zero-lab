---
id: TASK-313
title: 'zaddy: session_cookie enforcer does not see revocations'
status: Done
assignee: []
created_date: '2026-11-14T16:47:00Z'
updated_date: '2026-11-22 15:34'
labels: []
dependencies: []
ordinal: 328000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
pep.EnforcerSessionCookie (go/pep/session_cookie.go), which zaddy's forward_auth uses via the session_cookie enforcer type, opens zero-pep-proxy's session snapshot with the shared key and admits it until it expires (8 h by default). It never asks whether the session was signed out or rotated: zaddy has no Revocations, so a signed-out session keeps passing a zaddy-protected route. TASK-311 closed the same gap in zero-pep-proxy's own gateway, where Revocations are at hand. zaddy needs revocations from zero-pep-proxy: shared state (the Postgres bus and the pep:revoked: set, as TASK-310 asks for replays), a short snapshot TTL as the bound, or routing such checks through zero-pep-proxy's /oauth2/auth. Found while fixing TASK-311.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 A decision on how zaddy learns revocations is recorded
- [x] #2 A signed-out session's snapshot is refused by zaddy's session_cookie enforcer, with a test
- [x] #3 A revocation check that fails denies (rule 16), with a test
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. pep: SessionRevocations interface, key prefix/channel constants, Builder.WithSessionRevocations, Context.SessionRevocations; EnforcerSessionCookie checks it after opening the snapshot, denies on revoked, error or none configured.
2. kv/revoked: shared set of revoked IDs over kv.Store + kv.Bus (follow the bus, reconcile from keys every 30 s, local set; stale beyond a bound -> error).
3. zero-pep-proxy: kvRevocations replaced by kv/revoked with the pep constants.
4. zaddy: revocations_database_url in the global pep block; opens kv/postgres store + bus, follows at Start, stops at Stop; enforce_policy with a session_cookie enforcer refuses provisioning without it.
5. Tests, README, design.md.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
2026-11-22, maintainer: use kv, behind a domain-specific interface implemented at the host, as zeta-pdp-go does it.

Decision (2026-11-22, with the maintainer): zaddy learns revocations from zero-pep-proxy's kv, behind a domain interface the library defines and the host implements (the zeta-pdp-go pattern). pep defines SessionRevocations { Revoked(ctx, sid) (bool, error) } and the shared names SessionRevocationsKeyPrefix "pep:revoked:" and SessionRevocationsChannel "pep_revoked" (unchanged, so stored revocations stay readable). The new package kv/revoked is the shared set both hosts use: local set, filled over the kv.Bus (Postgres LISTEN/NOTIFY) and reconciled from the stored keys every 30 s, keys only (no store key ring needed); no DB read per request. It answers ErrStale for a sid it does not hold when the store was not read for 3 reconcile intervals, so a lost store denies (rule 16). zero-pep-proxy's kvRevocations is now kv/revoked. The enforcer reaches the revocations through pep.Context.SessionRevocations(), set by Builder.WithSessionRevocations; revoked, error or none configured all deny. zaddy: revocations_database_url in the global pep block; App.Start opens kv/postgres store + bus, follows before serving (start refused if it cannot), Stop ends it; enforce_policy provisioning refuses a policy with a SessionCookie enforcer at any depth without revocations_database_url (rule 17).
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
zaddy's SessionCookie enforcer now refuses the snapshot of a session zero-pep-proxy signed out or rotated. pep: SessionRevocations interface, shared key prefix and channel constants, Builder.WithSessionRevocations, Context.SessionRevocations; EnforcerSessionCookie denies on revoked, on a failing check and without revocations. New kv/revoked (shared revoked-ID set over kv.Store + kv.Bus, follows the bus, reconciles every 30 s, ErrStale past 90 s) replaces zero-pep-proxy's kvRevocations. zaddy: revocations_database_url, follows at Start, refuses SessionCookie policies without it. Tests: TestServerRule11_TheSessionCookieEnforcerRefusesARevokedSessionsSnapshot, TestServerRule16_AFailingRevocationCheckDeniesTheSessionCookie, TestServerRule16_ASessionCookieEnforcerWithoutRevocationsDenies (pep); TestServerRule11_ZaddyRefusesASignedOutSessionsSnapshot, TestServerRule17_ZaddyRefusesASessionCookiePolicyWithoutRevocations, TestServerRule17_ZaddyDoesNotStartWithoutItsRevocations (zaddy); kv/revoked Follow, staleness (TestServerRule16_AStaleSetCannotTellAnIDIsNotRevoked), rule 14/17 tests; zero-pep-proxy's revocation tests unchanged in substance and green. just check-changed passes in go/. Left: zaddy and pep/proxy require kv v0.6.0 / pep v0.29.0, which lack the new package and API; go mod tidy -diff outside the workspace fails until kv and pep are tagged and just sync runs.
<!-- SECTION:FINAL_SUMMARY:END -->
