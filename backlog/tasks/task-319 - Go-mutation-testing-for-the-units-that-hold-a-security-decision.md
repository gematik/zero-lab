---
id: TASK-319
title: 'Go: mutation testing for the units that hold a security decision'
status: To Do
assignee: []
created_date: '2026-11-14T20:52:00Z'
labels:
  - go
  - release
dependencies: []
ordinal: 334000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
docs/design/testing.md asks a unit that holds a security decision for a mutation threshold; the Rust workspace has one (TASK-53, TASK-281), the Go modules have none (go/Justfile has no mutation recipe). oidf, openid, dpop, nonce, pep are such units. Found while planning TASK-315.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A just recipe runs mutation testing on the Go units with a threshold and gates their release
<!-- AC:END -->
