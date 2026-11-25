---
id: TASK-430
title: 'kv/postgres: an index for prefix scans, a batched single cleaner, pgx''s pool'
status: Done
assignee: []
created_date: '2026-11-25T18:05:00Z'
updated_date: '2026-11-25T20:09:00Z'
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
- [x] #1 Keys and the Marker queries are range scans on an index, shown by the query plan in a test
- [x] #2 Cleanup deletes in batches and only one replica at a time runs it
- [x] #3 kv/postgres uses pgxpool; the contract suite and the existing gated tests pass unchanged
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
2026-11-25, on feat/kv-postgres-pool, not committed yet. The store is on pgxpool (conn.go: the configuration from DSN, user and password; SetMany as one pgx.Batch in a transaction; the bus publishes over a pool of two and listens over connections made from the same configuration); Migrate keeps *sql.DB, from OpenDB. Breaking, at the maintainer's word ('breaking change ok'): Open, OpenBus and OpenDB take user and password beside the DSN; a DSN with a user, a password or a parameter that names them (user, password, passfile, service, servicefile) is refused, as is a keyword DSN; PGUSER and PGPASSWORD are not used (tested with both set). SplitURL for hosts with one URL; the three hosts here use it and keep their configuration. Step 2: CREATE INDEX IF NOT EXISTS idx_kv_key_c ON kv (key COLLATE "C"); every statement by prefix or in order names that collation (underPrefix: key >= prefix AND key LIKE pattern; ORDER BY key COLLATE "C"). AC 1, by the plan with enable_seqscan off: before step 2 the prefix is a filter over rows read another way, after it an Index Cond on idx_kv_key_c with the prefix and the first key after it, for Keys and for MarkedOther. On the empty table of the test the planner reads the index as a bitmap and sorts; that it is a range of the index is what the test asserts, not the kind of scan. AC 2: Cleanup deletes batches of cleanupBatch (1000) with FOR UPDATE SKIP LOCKED, each in a transaction under pg_try_advisory_xact_lock (a transaction's lock, so it holds behind a pooler in transaction mode): 95 expired records in batches of 10 all removed, 2 live ones left; with the lock held by another session Cleanup returns 0 at once and leaves the records, and removes them afterwards. AC 3: the contract suite and every earlier test pass unchanged in what they assert; the migration tests now count from the number of released steps. kvtest gained two cases (order by bytes; an empty value), which memory, Postgres and MariaDB pass. Note: on the postgres:18-alpine image the database's own collation already orders by bytes (musl), so the order case cannot fail there; it would on a glibc or ICU collation. Verified: 33 tests (47 with their subtests) pass against Postgres 18 with -race, none skipped; zero-pep-proxy's revocations test over Postgres; just kv-mariadb-test; just lint clean. Seen and not changed: pgx's sslmode defaults to prefer, which falls back to plaintext without saying so, while kv/mariadb requires TLS unless the DSN says tls=false.

2026-11-25, released at the maintainer's word: go/kv v0.9.1 (kvtest's two cases), then go/kv/postgres v0.10.0 requiring it; zero-pdp, zero-pep-proxy and zaddy pinned to both, kv/mariadb to kv v0.9.1. just check in go/ passed on the branch before the merge and on the pinned state after it. The first just sync after the tags stopped on a fetch error of Go's module cache ('shallow file has changed since we read it') and passed when run again.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
kv/postgres takes user and password beside a DSN that is the address alone and refuses a DSN that carries them; it runs on pgx's pool; schema step 2 is an index of the keys by their bytes, over which Keys and the walk of the marks read a range, and keys are listed in that order; Cleanup deletes in batches, one replica at a time, under a transaction's advisory lock. kvtest says that keys are ordered by bytes and that an empty value is a value. Released as go/kv v0.9.1 and go/kv/postgres v0.10.0; the hosts here keep their one connection URL and take it apart with SplitURL.
<!-- SECTION:FINAL_SUMMARY:END -->
