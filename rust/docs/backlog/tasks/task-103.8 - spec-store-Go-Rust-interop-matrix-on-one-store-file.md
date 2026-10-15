---
id: TASK-103.8
title: 'spec/store: Go/Rust interop matrix on one store file'
status: To Do
assignee: []
created_date: '2026-10-15 17:45'
labels:
  - spec
  - tests
dependencies:
  - TASK-103.4
  - TASK-103.7
parent_task_id: TASK-103
priority: medium
ordinal: 109000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
interop/run.sh: Go writes state.db and Rust reads it, the reverse, and a concurrent take race across processes on one file; results in interop/matrix.md.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 round trips both ways pass
- [ ] #2 exactly one of two cross-language takes succeeds
<!-- AC:END -->
