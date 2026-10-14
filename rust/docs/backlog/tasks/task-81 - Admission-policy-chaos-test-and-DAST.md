---
id: TASK-81
title: 'Admission policy, chaos test and DAST'
status: To Do
assignee: []
created_date: '2026-10-14 20:44'
labels:
  - go
  - release
  - tests
dependencies: []
references:
  - go/docs/design.md
priority: medium
ordinal: 79000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
No admission policy enforces signed images, no chaos test takes a zone down, no DAST runs (server rules 25, 26).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 an admission policy for signed images by digest, a chaos test for zone and primary loss with replay checks, and DAST against every exposed endpoint
<!-- AC:END -->
