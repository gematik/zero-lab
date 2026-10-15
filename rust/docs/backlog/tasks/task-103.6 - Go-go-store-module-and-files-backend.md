---
id: TASK-103.6
title: 'Go: go/store module and files backend'
status: To Do
assignee: []
created_date: '2026-10-15 17:45'
labels:
  - go
  - keys
  - security
  - fuzz
dependencies:
  - TASK-103.1
parent_task_id: TASK-103
priority: medium
ordinal: 107000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Standard library only: interfaces, Store, envelope, derivation, memory and files backends, key-file wrapper, profile resolution.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 passes the spec/store vectors and scenarios in tests named after the STORE rules
- [ ] #2 fuzz targets for the envelope and keyring-file parsers
- [ ] #3 no third-party requirement in go/store/go.mod
<!-- AC:END -->
