---
id: TASK-430
title: 'kv/postgres: an index for prefix scans, a batched single cleaner, pgx''s pool'
status: To Do
assignee: []
created_date: '2026-11-25T18:05:00Z'
labels:
  - go
dependencies:
  - TASK-428
documentation:
  - >-
    backlog/docs/doc-7 -
    kv-durable-store-cache-and-reliable-pub-sub-over-Postgres-and-MariaDB-plan-for-review.md
priority: medium
ordinal: 443000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
doc-7, Postgres features. key LIKE 'prefix%' on a text primary key with the database's default collation cannot use the index: every Keys and Marker query scans the table. Cleanup deletes all expired rows in one statement and every replica runs it. database/sql hides pgx's batches and prepared-statement control. Plan: a second index for prefixes (COLLATE "C" or text_pattern_ops) as an expand step, the column change later; Cleanup under pg_try_advisory_lock, in batches; pgxpool instead of database/sql behind the same kv.Store (confirmed in review; no new module).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Keys and the Marker queries are range scans on an index, shown by the query plan in a test
- [ ] #2 Cleanup deletes in batches and only one replica at a time runs it
- [ ] #3 kv/postgres uses pgxpool; the contract suite and the existing gated tests pass unchanged
<!-- AC:END -->
