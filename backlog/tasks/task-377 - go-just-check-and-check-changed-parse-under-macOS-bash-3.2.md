---
id: TASK-377
title: 'go: just check and check-changed parse under macOS bash 3.2'
status: Done
assignee: []
created_date: '2026-11-18 08:29'
updated_date: '2026-11-18 08:45'
labels:
  - go
  - tooling
dependencies: []
ordinal: 392000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The recipes _each and _each_check in go/Justfile loop over ${GO_MODULES:-$(find … \; | sort)}. bash 3.2.57, the only bash macOS ships, refuses a pipe inside a command substitution inside a parameter expansion ('syntax error near unexpected token |'), so every recipe built on them (lint, test, mod-check, check, check-changed) fails before it runs a check. Found on 2026-11-18 while checking TASK-376.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 just check and just check-changed run under /bin/bash 3.2 on macOS, with and without GO_MODULES
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
The module list is read into a variable before the loop in _each and _each_check. just check ran green under /bin/bash 3.2.57 without GO_MODULES; with GO_MODULES set the same lines take the variable.
<!-- SECTION:NOTES:END -->
