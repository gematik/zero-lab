---
id: TASK-196
title: 'pep, pep/proxy: smaller log and failure paths'
status: Done
assignee: []
created_date: '2026-11-02T22:59:00Z'
updated_date: '2026-11-05T19:25:00Z'
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

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Closed without change: the realIP part no longer applies, and the revocation IDs over Postgres NOTIFY are hashes of the cookie.
<!-- SECTION:FINAL_SUMMARY:END -->
