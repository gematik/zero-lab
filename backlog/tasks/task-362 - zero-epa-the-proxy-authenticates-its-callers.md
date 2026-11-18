---
id: TASK-362
title: 'zero-epa: the proxy authenticates its callers'
status: To Do
assignee: []
created_date: '2026-11-16T22:52:00Z'
updated_date: '2026-11-18T06:22:00Z'
labels:
  - epa
  - security
  - server
  - parked
dependencies: []
priority: high
ordinal: 377000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Found by the rule 28 audit of TASK-321 (2026-11-17): zero-epa's proxy listens on :8082 and answers every caller, though it acts with the SMC-B identity it holds (authorization at the Aktensystem, entitlement, record access). Anyone who reaches the port uses that identity. servers.md (authentication of every request; least privilege). Decide how callers authenticate (a token from the PEP, mTLS, a local socket only) and refuse others before any work.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A request without the configured authentication is refused before it reaches a handler, with a test
- [ ] #2 The default binding and the documentation say who may call the proxy
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
2026-11-18: the maintainer postponed the decision on how callers authenticate ("we do it later"). Options weighed: loopback bind by default plus a caller token from a file; a PEP access token; mTLS; a Unix socket only.
<!-- SECTION:NOTES:END -->
