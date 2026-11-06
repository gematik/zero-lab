---
id: TASK-98.2
title: 'go/tipki/titls: web profile and tls.Config per profile'
status: To Do
assignee: []
created_date: '2026-11-06T14:01:00Z'
labels:
  - go
  - security
dependencies: []
parent_task_id: TASK-98
ordinal: 245000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
web profile (system roots plus the TLSV web rules: keys, signatures, name, validity, OCSP or CRL) and a tls.Config constructor per profile with versions, suites and curves of handshake.json; bounded verdict cache (TLSV-050) and an atomically swapped trust snapshot.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 the web corpus cases pass
- [ ] #2 the configs follow handshake.json and a caller cannot weaken them
- [ ] #3 the verdict cache is bounded and the ti snapshot swaps atomically, with tests
<!-- AC:END -->
