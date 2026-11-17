---
id: TASK-373
title: 'pep/proxy: zero-pep-proxy hands idpd its logger'
status: To Do
assignee: []
created_date: '2026-11-17T06:45:00Z'
labels:
  - pep-proxy
  - idpd
  - go
dependencies: []
priority: medium
ordinal: 388000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Since TASK-289 idpd's BundleTrust rereads its mounted bundle in the background and logs a failed reload to ClientConfig.Logger (nil logs nothing, go/docs/design.md §2). zero-pep-proxy pins an older idpd and sets no logger, so a bad bundle replacement there is silent until the store in use reaches its age limit and logins fail.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 zero-pep-proxy passes its logger to idpd's ClientConfig and a failed bundle reload appears in its log, with a test
<!-- AC:END -->
