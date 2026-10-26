---
id: TASK-143
title: 'Go: agent subcommand with an embedded AGENTS.md for every CLI'
status: To Do
assignee: []
created_date: '2026-10-26 11:07'
updated_date: '2026-10-26 11:07'
labels:
  - go
  - docs
dependencies:
  - TASK-142
priority: low
ordinal: 152000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Only ti prints a guide for agents. The Go binaries (zero-epa, zero-pdp, zero-caddy, zero-pep-proxy, zero-bff, zero-bff-pdp) have none, so a skill for them would have to carry the knowledge itself, which the convention forbids. Each gets an AGENTS.md beside its main package, embedded with go:embed and printed by `<bin> agent`, as ti does.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Each Go CLI binary has an AGENTS.md and an agent subcommand printing it from the binary
- [ ] #2 A test per binary asserts agent prints the embedded file unchanged
- [ ] #3 go/docs/development.md names the convention by link, without restating it
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
decision-9
<!-- SECTION:NOTES:END -->
