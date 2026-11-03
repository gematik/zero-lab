---
id: TASK-196
title: 'pep, pep/proxy: smaller log and failure paths'
status: To Do
assignee: []
created_date: '2026-11-02T22:59:00Z'
labels:
  - go
  - security
dependencies: []
priority: low
ordinal: 206000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
realIP trusts X-Forwarded-For in logs. An invalid JWKS source in pep also reads as 401. Revocation sids, which are cookie hashes, go in clear over Postgres NOTIFY.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Each has a decision or a fix
<!-- AC:END -->
