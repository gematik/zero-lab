---
id: TASK-73
title: 'Servers: refuse insecure production configuration at start-up'
status: To Do
assignee: []
created_date: '2026-10-14 20:44'
labels:
  - go
  - server
  - pdp
dependencies: []
references:
  - go/docs/design.md
priority: medium
ordinal: 71000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
pdp/authzserver falls back to an in-memory store; no start-up validation rejects insecure production configuration (server rule 17).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 a production mode in which every server exits on an in-memory store, TEST-ONLY material, disabled checks, missing keys or debug endpoints
<!-- AC:END -->
