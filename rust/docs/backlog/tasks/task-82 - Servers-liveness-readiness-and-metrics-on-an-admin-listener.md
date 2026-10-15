---
id: TASK-82
title: 'Servers: liveness, readiness and metrics on an admin listener'
status: To Do
assignee: []
created_date: '2026-10-14 20:44'
labels:
  - go
  - server
dependencies: []
references:
  - docs/design/servers.md
  - go/docs/design.md
priority: medium
ordinal: 80000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The servers have timeouts and graceful shutdown but no health or metrics endpoints and no admin listener (server rules 8, 23).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 liveness and readiness reflecting real state, metrics, all on a separate admin listener with its own authentication
<!-- AC:END -->
