---
id: TASK-86
title: 'Go just check: tests, race detector, govulncheck, golangci-lint'
status: In Progress
assignee: []
created_date: 2026-10-14 20:44
updated_date: '2026-11-02T15:42:00Z'
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
- [x] #1 just check runs go test -race, govulncheck and golangci-lint in every module, and the pinned tools work with the current Go
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
just check now runs lint, golangci, modernize, vuln, mod-check, test, test-race and api-lint in every module; gated variables are cleared first. govulncheck moved to 1.9.0 because 1.4.0 crashed on zaddy and hid five vulnerabilities; Caddy 2.11.7 removes them. Caps on golangci findings removed (928 real findings). Real findings became TASK-178 to TASK-188; their nolint lines name the task.
<!-- SECTION:NOTES:END -->
