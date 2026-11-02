---
id: TASK-86
title: 'Go just check: tests, race detector, govulncheck, golangci-lint'
status: Done
assignee: []
created_date: 2026-10-14 20:44
updated_date: '2026-11-02T19:06:00Z'
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

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
just check runs vet, staticcheck, golangci-lint, modernize, govulncheck, go mod tidy -diff, go mod verify, and tests with and without the race detector in all 17 modules, and passes. It found five vulnerabilities in zaddy (Caddy 2.11.7) and a JWK bug (TASK-189). Real findings became TASK-178 to TASK-188.
<!-- SECTION:FINAL_SUMMARY:END -->
