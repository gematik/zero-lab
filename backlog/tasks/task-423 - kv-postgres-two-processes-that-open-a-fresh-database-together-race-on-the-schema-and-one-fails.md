---
id: TASK-423
title: >-
  kv/postgres: two processes that open a fresh database together race on the
  schema, and one fails
status: To Do
assignee: []
created_date: '2026-11-24T21:16:00Z'
labels:
  - go
dependencies: []
ordinal: 436000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Found in zeta-authserver-go (its TASK-167, and once before in TASK-166) on 2026-11-24: two replicas started at the same moment against an empty database, in a kind cluster and in docker compose. One of them ended at start with: host: database: kv/postgres: schema: ERROR: duplicate key value violates unique constraint "pg_type_typname_nsp_index" (SQLSTATE 23505). postgres.Open runs CREATE TABLE IF NOT EXISTS kv and the statements after it with no lock; IF NOT EXISTS does not make concurrent creation safe in Postgres, the second session fails on the catalog's unique index. With the dependency pinned there (kv v0.4.1-0.20261118220232-3bd241531a9f). Under Kubernetes the container is restarted and then starts, so a rollout only shows a restart; a first installation with several replicas hits it regularly. Possible: a transaction-scoped advisory lock (pg_advisory_xact_lock) around the schema statements, so that the second process waits and then finds the table.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Several processes opening an empty database at the same moment all succeed, held by a test that starts them together
<!-- AC:END -->
