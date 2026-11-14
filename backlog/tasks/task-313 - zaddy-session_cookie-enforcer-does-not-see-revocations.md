---
id: TASK-313
title: 'zaddy: session_cookie enforcer does not see revocations'
status: To Do
assignee: []
created_date: '2026-11-14T16:47:00Z'
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
- [ ] #1 A decision on how zaddy learns revocations is recorded
- [ ] #2 A signed-out session's snapshot is refused by zaddy's session_cookie enforcer, with a test
- [ ] #3 A revocation check that fails denies (rule 16), with a test
<!-- AC:END -->
