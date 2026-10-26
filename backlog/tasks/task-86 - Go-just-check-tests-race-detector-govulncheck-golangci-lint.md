---
id: TASK-86
title: 'Go just check: tests, race detector, govulncheck, golangci-lint'
status: To Do
assignee: []
created_date: '2026-10-14 20:44'
labels:
  - go
  - tooling
dependencies:
  - TASK-38
references:
  - docs/design/testing.md
  - go/docs/design.md
priority: medium
ordinal: 84000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
just check runs lint and modernize only; the installed govulncheck fails on the current Go.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 just check runs go test -race, govulncheck and golangci-lint in every module, and the pinned tools work with the current Go
<!-- AC:END -->
