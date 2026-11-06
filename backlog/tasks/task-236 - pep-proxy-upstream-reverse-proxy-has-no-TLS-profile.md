---
id: TASK-236
title: 'pep/proxy: upstream reverse proxy has no TLS profile'
status: To Do
assignee: []
created_date: '2026-11-06T17:16:00Z'
labels:
  - go
  - security
dependencies: []
priority: medium
ordinal: 252000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Found in TASK-98.5's inventory: the zero-pep-proxy gateway forwards to its upstream with an http.Transport whose TLS is Go's default, not a spec/pki-validation profile. Decide the upstream's profile (web for an internet upstream; a local upstream may be plain or mTLS) and wire it.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 the gateway's upstream transport verifies under the profile chosen for it, or the exception is documented
<!-- AC:END -->
