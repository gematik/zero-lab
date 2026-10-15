---
id: TASK-110
title: 'kv: bring go/kv onto the spec/store contract'
status: To Do
assignee: []
created_date: '2026-10-15 17:46'
labels:
  - go
  - server
  - security
dependencies:
  - TASK-103.1
references:
  - docs/design/servers.md
priority: medium
ordinal: 116000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Once spec/store exists, make go/kv seal values (TASK-71) and hash keys with the same envelope and derivation, with per-tenant data keys (TASK-80), migrating expand-migrate-contract (server rule 22).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 kv records in Postgres are spec/store envelopes
<!-- AC:END -->
