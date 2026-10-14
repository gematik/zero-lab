---
id: TASK-68
title: 'Go: enforce CGO_ENABLED=0 in just check and local builds'
status: To Do
assignee: []
created_date: '2026-10-14 20:43'
labels:
  - go
  - tooling
dependencies: []
references:
  - go/docs/design.md
priority: medium
ordinal: 66000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Every Dockerfile sets CGO_ENABLED=0, but just check and local builds do not enforce it (goal 10).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 just check fails when a module needs cgo; local build recipes set CGO_ENABLED=0
<!-- AC:END -->
