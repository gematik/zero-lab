---
id: TASK-103.7
title: 'Go: go/store/sqlite backend and zero-epa profiles'
status: To Do
assignee: []
created_date: '2026-10-15 17:45'
updated_date: '2026-10-15 18:19'
labels:
  - go
  - epa
  - deps
dependencies:
  - TASK-103.6
parent_task_id: TASK-103
priority: medium
ordinal: 108000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
SQLite backend as its own module so go/store stays dependency-free; driver ncruces/go-sqlite3 (no cgo) or modernc.org/sqlite after maintainer approval. zero-epa gains --profile and opens the shared store.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 driver approved with transitive cost recorded
- [ ] #2 passes the operation scenarios
- [ ] #3 zero-epa --profile opens the profile's store
- [ ] #4 zero-epa implements the same section L commands with the same names and doctor JSON as ti
<!-- AC:END -->
