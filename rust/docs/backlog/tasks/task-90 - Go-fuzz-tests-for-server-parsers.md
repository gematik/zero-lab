---
id: TASK-90
title: Go fuzz tests for server parsers
status: To Do
assignee: []
created_date: '2026-10-14 20:44'
labels:
  - go
  - fuzz
dependencies: []
references:
  - go/docs/design.md
priority: medium
ordinal: 88000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Fuzzing covers the frozen brainpool and pkcs12 only (goal 8).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 native fuzz tests for DPoP proofs, client assertions, PAR and token requests, entity statements, ID tokens and JWKS, nonces, VAU messages and pep routes, with committed crashers
<!-- AC:END -->
