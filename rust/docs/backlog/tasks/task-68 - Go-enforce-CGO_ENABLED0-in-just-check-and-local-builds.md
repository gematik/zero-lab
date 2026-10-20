---
id: TASK-68
title: 'Go: enforce CGO_ENABLED=0 in just check and local builds'
status: Done
assignee: []
created_date: '2026-10-14 20:43'
updated_date: '2026-10-20 16:51'
labels:
  - go
  - tooling
dependencies: []
references:
  - docs/interop.md
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
- [x] #1 just check fails when a module needs cgo; local build recipes set CGO_ENABLED=0
<!-- AC:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
go/justfile exports CGO_ENABLED=0 for every recipe (build, lint, modernize, tests), so a module or dependency that needs cgo fails just check rather than the Docker build.
<!-- SECTION:FINAL_SUMMARY:END -->
