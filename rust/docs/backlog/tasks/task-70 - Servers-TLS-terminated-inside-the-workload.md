---
id: TASK-70
title: 'Servers: TLS terminated inside the workload'
status: To Do
assignee: []
created_date: '2026-10-14 20:43'
labels:
  - go
  - server
dependencies: []
references:
  - docs/design/servers.md
  - go/docs/design.md
priority: medium
ordinal: 68000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
No server terminates TLS itself; TLS ends at an ingress outside the workload (server rule 5).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 each server can serve TLS (and mTLS) itself with a crypto.Signer key; deployments end TLS inside the workload
<!-- AC:END -->
