---
id: TASK-107
title: 'kv/postgres: expires_at computed from the client clock'
status: To Do
assignee: []
created_date: '2026-10-15 17:45'
labels:
  - go
  - server
dependencies: []
references:
  - docs/design/servers.md
priority: medium
ordinal: 113000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
go/kv/postgres/postgres.go:116 sets expires_at = time.Now().Add(ttl) on the client but reads compare with the database now(); skew between replicas shortens or lengthens TTLs of single-use values.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 expires_at derives from the database clock (now() + interval) or skew is bounded and tested
<!-- AC:END -->
