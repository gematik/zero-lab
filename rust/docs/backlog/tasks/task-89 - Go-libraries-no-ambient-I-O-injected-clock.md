---
id: TASK-89
title: 'Go libraries: no ambient I/O, injected clock'
status: To Do
assignee: []
created_date: '2026-10-14 20:44'
labels:
  - go
dependencies: []
references:
  - docs/architecture.md
  - go/docs/design.md
priority: medium
ordinal: 87000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
pep/proxy and bff/gateway read environment variables themselves; about 40 time.Now() calls outside tests in decision code (goals 3 and 6).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 configuration read only in cmd/; decision code takes the time as a parameter or func() time.Time
<!-- AC:END -->
