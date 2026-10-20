---
id: TASK-106
title: 'kv: secret-bearing keys stored in plain text'
status: To Do
assignee: []
created_date: '2026-10-15 17:45'
labels:
  - go
  - pdp
  - security
dependencies: []
references:
  - docs/design/servers.md
priority: high
ordinal: 112000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
go/pdp/authzserver/session_store_kv.go:36-56 writes index keys as:code:<code> and as:refresh:<token>; the kv key column is plain text in Postgres (go/kv/postgres/postgres.go:44), so authorization codes and refresh tokens are readable by whoever reads the database. Sealing values alone (TASK-71) does not cover this. Server rules 5 and 10 (keyed by a hash).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 no secret value appears in a kv key; index keys use a keyed hash
<!-- AC:END -->
