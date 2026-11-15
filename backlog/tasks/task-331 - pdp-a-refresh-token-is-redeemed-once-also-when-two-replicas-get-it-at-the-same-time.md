---
id: TASK-331
title: >-
  pdp: a refresh token is redeemed once, also when two replicas get it at the
  same time
status: To Do
assignee: []
created_date: '2026-11-15T09:28:00Z'
labels:
  - pdp
  - go
  - security
dependencies: []
ordinal: 346000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Found by the review of TASK-316: tokenEndpointRefreshToken (go/pdp/authzserver/token.go ~332-370) looks the session up with a plain Get by the refresh token, compares, rotates and saves. Two replicas that receive the same refresh token at once both read the matching session, both rotate it and both issue tokens; the last save wins. servers.md rule 11 names refresh-token rotation as ACID single-use state. DPoP binding limits who can exploit it. Fix by a Take on the refresh index (as codes and request URIs are taken) or by compare-and-swap (TASK-305).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Of two concurrent refreshes with the same token exactly one succeeds, shown by a test through the handlers against a store with atomic Take
<!-- AC:END -->
