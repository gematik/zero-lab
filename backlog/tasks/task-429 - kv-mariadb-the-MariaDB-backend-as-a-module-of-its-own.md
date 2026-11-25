---
id: TASK-429
title: 'kv/mariadb: the MariaDB backend as a module of its own'
status: Done
assignee: []
created_date: '2026-11-25T18:05:00Z'
updated_date: '2026-11-25T19:40:00Z'
labels:
  - go
dependencies:
  - TASK-428
documentation:
  - >-
    backlog/docs/doc-7 -
    kv-durable-store-cache-and-reliable-pub-sub-over-Postgres-and-MariaDB-plan-for-review.md
priority: high
ordinal: 442000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
doc-7, MariaDB, the second backend. Required by the maintainer (2026-11-25), in every topology: a single node, a primary with replicas, Galera with one or several writing nodes. Driver github.com/go-sql-driver/mysql (approved 2026-11-25; v1.10.2 looked at that day: pure Go, no cgo, no unsafe, requires filippo.io/edwards25519 v1.2.0 alone); its evaluation under docs/conventions/dependencies.md is recorded with this task. Scope: kv.Store, Swapper and Marker over MariaDB with the statements of doc-7's table (DELETE … RETURNING, INSERT … ON DUPLICATE KEY UPDATE with ROW_COUNT(), a binary key column for prefix scans, expiry from the database clock), its numbered steps and Migrate (a row of kv_schema locked FOR UPDATE; every DDL statement commits implicitly, so steps are single repeatable statements), the version check and WithMigrate as in kv/postgres. No GET_LOCK and no AUTO_INCREMENT for order: neither holds across Galera's nodes. Every statement is written to be repeated on a deadlock or certification failure (errors 1213, 1205), a bounded number of times. wsrep_sync_wait is configurable, WithSyncWait(mode), automatic by default (on when the server reports wsrep_on). The facts of doc-7 are from documentation: the contract tests prove them, and if one does not hold the plan comes back for review.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 go/kv/mariadb is a module in go.work requiring go/kv and the driver, with its row in AGENTS.md and the driver's evaluation recorded
- [x] #2 The contract suite of kv/kvtest passes gated by TEST_MARIADB_DSN against the oldest and the newest LTS release maintained at the time, named in the development guide's gated-suite table
- [x] #3 Against a Galera cluster of three writing nodes the single-use operations (Take, SetIfAbsent, Swap) have exactly one winner when run concurrently through different nodes, and a value set through one node is found through another with sync wait on
- [x] #4 Migrate, the version check and WithMigrate behave as in kv/postgres, with the same tests
- [x] #5 Each statement of doc-7's MariaDB table that did not hold as written is recorded, and doc-7 corrected
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
2026-11-25, on feat/kv-mariadb, not committed yet. go/kv/mariadb: mariadb.go (Open, OpenDB, the store, Swapper, Marker, WithMark, WithMigrate, WithSyncWait, WithTLS, the DSN as a URL), migrate.go (steps, Migrate with To and Contract, the version check through kv/schema); in go.work, the Justfile's lists and AGENTS.md. Driver go-sql-driver/mysql v1.10.2 with its reason beside the requirement in go.mod (looked at 2026-11-25: pure Go, no cgo, no unsafe; requires filippo.io/edwards25519 v1.2.0 alone, pure Go without unsafe, assembly for amd64). Verified with just kv-mariadb-test (new; Docker): 28 tests against MariaDB 10.11.19 and 12.3.3, none skipped, with -race; the Galera suite against three writing nodes of 12.3. What the tests showed against doc-7, corrected there: (1) no lock serialises migrators: DDL commits and releases a row lock, so steps are single repeatable statements, proven by running each twice and by migrators through three nodes at once; (2) error 1317 (query interrupted) joins 1213 and 1205 as right to repeat: a node breaks a statement off for a schema change of the cluster; (3) Swap is SELECT FOR UPDATE plus UPDATE in one transaction, since an UPDATE counts changed rows; (4) SetIfAbsent is one INSERT ON DUPLICATE KEY UPDATE whose assignments read expires_at before they set it, reported by its row count; (5) with the repeating taken out the Galera contract fails with 1213, so one winner across nodes rests on it; (6) wsrep_sync_wait=7: 300 of 300 found through another node with it, 11, 1 and 0 of 300 missed without in three runs; (7) keys bounded at 1024 bytes and refused beyond, sessions in strict mode and UTC; (8) the official image's health check fails on a node that joined (it takes the donor's health-check user), so the compose file checks as root. Not proven: a primary with replicas; the cost of the wait (TASK-431). just check in go/ passed.

2026-11-25, maintainer: no user and no password in the DSN; they are parameters. Open(ctx, dsn, user, password, opts...) and OpenDB(dsn, user, password, opts...); the DSN is mariadb://host:port/database with tls=false as its one parameter, and one that carries a user or a password is refused without repeating it. A password is taken as it is (tested with URL delimiters and escapes in it). Compared before: zeta-guard-helm 2.0.2 gives the notification service and Keycloak a JDBC URL without credentials and username and password from a secret; zeta-authserver-go puts the whole URL with the password into a file. The tests take TEST_MARIADB_DSN, TEST_MARIADB_USER and TEST_MARIADB_PASSWORD. just kv-mariadb-test passed again on this state. kv/postgres still takes the credentials in its URL: a task to come, if the maintainer wants it in line.

2026-11-25, released at the maintainer's word: go/kv/mariadb v0.1.0, requiring go/kv v0.9.0. just check in go/ passed before the merge (one earlier run failed in pep/proxy's TestServerRule10_SnapshotWrongKeyAndTamper, which fails by chance about once in 300 runs and is not touched here: TASK-435). A module outside the workspace gets the tag with go get, builds, and has no pgx in its module graph.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
go/kv/mariadb is the MariaDB backend of kv, a module of its own on go-sql-driver/mysql: kv.Store, Swapper and Marker, the schema in numbered repeatable steps with Migrate, Open without DDL, WithMigrate. It rests on nothing that holds on one node only, repeats a statement that lost against another writer, and in a cluster waits for the cluster's commits; the address is the DSN, user and password are parameters beside it. Proven by just kv-mariadb-test against MariaDB 10.11 and 12.3 and with every call through another writing node of a Galera cluster of three; doc-7 corrected where the tests said otherwise. Released as go/kv/mariadb v0.1.0.
<!-- SECTION:FINAL_SUMMARY:END -->
