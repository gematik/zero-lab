---
id: TASK-428
title: >-
  kv: numbered migrations with Migrate, a version check in Open and WithMigrate;
  kv/schema and kv/kvtest
status: To Do
assignee: []
created_date: '2026-11-25T18:05:00Z'
labels:
  - go
dependencies:
  - TASK-427
documentation:
  - >-
    backlog/docs/doc-7 -
    kv-durable-store-cache-and-reliable-pub-sub-over-Postgres-and-MariaDB-plan-for-review.md
priority: high
ordinal: 441000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Step 1 of doc-7 (Schema creation and migrations). Today postgres.Open applies the schema on every start, under an advisory lock since go/kv v0.7.0 (TASK-423), so a server's database role must own the tables. Plan: kv/schema in the core (numbered steps, the version check; no SQL dialect, no driver); kv/postgres keeps embedded numbered steps and a table kv_schema(version, applied_at); Migrate(ctx, db, to, opts) applies them with one migrator at a time, each step one transaction, a contract step only with Contract(). Open runs no DDL by default: it reads kv_schema and refuses a version below what it needs or above what it knows, naming both (servers.md rule 17). With WithMigrate(), off by default and set by the host, Open first applies the missing expand steps under the same lock and reports it. The existing schema becomes step 1 so that a database of today is adopted without change. No migrate command, image or Job here: those are the host's. Rights are documented, not granted. kv/kvtest holds the contract tests every backend runs (Store, Swapper, Marker, Resealer above them). Breaking for hosts: a host runs Migrate before its rollout or sets WithMigrate; the release notes say so.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 kv/schema and kv/kvtest exist in go/kv and import no driver; kv/postgres runs the contract suite gated by TEST_DATABASE_URL, memory runs it always
- [ ] #2 Migrate applies numbered steps once, with one migrator at a time, proven by a test that starts several together on an empty database; a database created by go/kv v0.7.0 is adopted without a change of data
- [ ] #3 Open without WithMigrate runs no DDL (proven with a role that has DML rights only) and refuses an older or an unknown newer schema version, naming both
- [ ] #4 Open with WithMigrate applies missing expand steps and never a contract step
- [ ] #5 The rights a server role needs are documented in the backend; whether servers.md gains the rule that a server's role has no DDL rights is decided with the maintainer
<!-- AC:END -->
