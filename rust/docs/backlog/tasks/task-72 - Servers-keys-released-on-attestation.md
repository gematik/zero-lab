---
id: TASK-72
title: 'Servers: keys released on attestation'
status: To Do
assignee: []
created_date: '2026-10-14 20:44'
labels:
  - go
  - server
  - keys
dependencies: []
references:
  - go/docs/design.md
priority: medium
ordinal: 70000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Keys come from files without attestation-bound release (server rule 6).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 a key broker or KMS adapter that releases workload keys only to a verified measurement, delivered as *_PATH files
<!-- AC:END -->
