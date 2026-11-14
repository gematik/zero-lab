---
id: TASK-311
title: 'pep/proxy: gateway snapshot routes ask Revocations'
status: Done
assignee: []
created_date: '2026-11-14T15:21:00Z'
updated_date: '2026-11-14T16:54:00Z'
labels: []
dependencies: []
ordinal: 326000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
GateSnapshot (go/pep/proxy/gateway.go, around line 126) checks a session snapshot with pep.NewEnforcerSessionCookie and the snapshot keys only; it never asks Revocations. A snapshot of a session that was signed out or rotated therefore still passes the gateway's snapshot routes until its exp (8 h by default); only /oauth2/auth checks revocations. Found by the review of refactor/module-stores (TASK-307); it predates that branch.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 A revoked session's snapshot is refused on gateway snapshot routes, with a test
- [x] #2 A failing revocation check denies there too (rule 16), with a test
<!-- AC:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
The gateway's snapshot gate (pep/proxy gateway_context.go snapshotGate) opens the snapshot itself and asks Revocations, as /oauth2/auth does: a signed-out or rotated session is refused on gate: snapshot routes at once instead of until its snapshot expires; a failing check denies (rule 16); a snapshot route without revocations is refused at start (rule 17). Tests for each; the first two fail without the fix. zaddy's session_cookie enforcer has the same gap: TASK-313. Branch bugfix/pep-gateway-revocations.
<!-- SECTION:FINAL_SUMMARY:END -->
