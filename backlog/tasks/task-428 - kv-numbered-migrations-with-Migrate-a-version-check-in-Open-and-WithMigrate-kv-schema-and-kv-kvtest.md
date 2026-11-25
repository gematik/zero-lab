---
id: TASK-428
title: >-
  kv: numbered migrations with Migrate, a version check in Open and WithMigrate;
  kv/schema and kv/kvtest
status: In Progress
assignee: []
created_date: '2026-11-25T18:05:00Z'
updated_date: '2026-11-25T18:41:00Z'
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
- [x] #1 kv/schema and kv/kvtest exist in go/kv and import no driver; kv/postgres runs the contract suite gated by TEST_DATABASE_URL, memory runs it always
- [x] #2 Migrate applies numbered steps once, with one migrator at a time, proven by a test that starts several together on an empty database; a database created by go/kv v0.7.0 is adopted without a change of data
- [x] #3 Open without WithMigrate runs no DDL (proven with a role that has DML rights only) and refuses an older or an unknown newer schema version, naming both
- [x] #4 Open with WithMigrate applies missing expand steps and never a contract step
- [ ] #5 The rights a server role needs are documented in the backend; whether servers.md gains the rule that a server's role has no DDL rights is decided with the maintainer
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
2026-11-25, on feat/kv-migrations, not committed yet. kv/schema (Step, Applied, Validate, Version, Pending, Needs, Check, VersionError; no SQL, no driver) and kv/kvtest (Store with Swapper, Marker) in go/kv; memory and Postgres run the contract suite. kv/postgres: steps with their SQL (step 1 is the schema of before, every statement of which changes nothing where it ran), kv_schema(version, name, contract, applied_at), Migrate(ctx, db, opts...) with To and Contract, each step one transaction under pg_advisory_xact_lock; Open runs no DDL and checks the version; WithMigrate applies pending expand steps first. Deviation from doc-7, corrected there: Open refuses a missing step and an unknown contract step, not any version above what it knows, so that a replica of release N restarts while N+1's expand steps are applied (rule 22); kv_schema therefore records which steps are contract steps. Logging through slog, as reap.go and bus.go do. The hosts here (zero-pdp, zero-pep-proxy, zaddy) pass WithMigrate and so behave as before; a setting for it would be a host feature. just mod-check treats kvtest as a test package. Verified against Postgres 18: 39 tests pass with -race, none skipped; with the advisory lock taken out the two tests that start many at once fail with the 23505 of TASK-423; zero-pep-proxy's revocations test over Postgres passes; just lint is clean. Open: just check's tidy check outside the workspace needs kv with the new packages on the remote (push, just sync). AC 5: the rights are in Open's documentation; the servers.md rule is the maintainer's decision.
<!-- SECTION:NOTES:END -->
