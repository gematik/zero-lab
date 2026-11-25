---
id: TASK-423
title: >-
  kv/postgres: two processes that open a fresh database together race on the
  schema, and one fails
status: Done
assignee: []
created_date: '2026-11-24T21:16:00Z'
updated_date: '2026-11-25T06:19:00Z'
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
- [x] #1 Several processes opening an empty database at the same moment all succeed, held by a test that starts them together
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
2026-11-25, on fix/kv-postgres-schema-race. Reproduced with a test that opens a fresh database from 8 sessions at once, 5 rounds: without a lock most sessions fail with the reported 23505 on pg_type_typname_nsp_index, and one round also showed deadlock detected (40P01) from the ALTER statements. Fix: applySchema runs schemaSQL in one transaction under pg_advisory_xact_lock; the second session waits for the commit and finds the schema. 100 rounds pass after it. just check in go/ passed; the Postgres suite (16 tests, -race, Postgres 18) passed with none skipped.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
postgres.Open applies the schema in one transaction under a transaction-scoped advisory lock; a test opens an empty database from 8 sessions at once and failed before the fix with the reported error. Released as go/kv v0.7.0.
<!-- SECTION:FINAL_SUMMARY:END -->
