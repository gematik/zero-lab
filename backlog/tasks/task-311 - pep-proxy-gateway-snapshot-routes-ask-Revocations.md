---
id: TASK-311
title: 'pep/proxy: gateway snapshot routes ask Revocations'
status: In Progress
assignee: []
created_date: '2026-11-14T15:21:00Z'
updated_date: '2026-11-14T16:44:00Z'
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
- [ ] #1 A revoked session's snapshot is refused on gateway snapshot routes, with a test
- [ ] #2 A failing revocation check denies there too (rule 16), with a test
<!-- AC:END -->
