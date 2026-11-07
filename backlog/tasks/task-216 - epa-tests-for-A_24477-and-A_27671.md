---
id: TASK-216
title: 'epa: tests for A_24477 and A_27671'
status: In Progress
assignee: []
created_date: '2026-11-05T21:24:00Z'
updated_date: '2026-11-07T10:27:00Z'
labels:
  - go
dependencies: []
ordinal: 223000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
epa has no test for A_24477 (VAU-nonPU-Tracing header) and none for A_27671 (single-use token), although entitlements.go cites A_27671. Found while naming tests (TASK-83).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 a test named after A_24477 proves the tracing header rule
- [ ] #2 a test named after A_27671 proves the single-use token rule
<!-- AC:END -->
