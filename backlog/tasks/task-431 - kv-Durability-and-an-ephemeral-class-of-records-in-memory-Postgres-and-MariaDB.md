---
id: TASK-431
title: >-
  kv: Durability and an ephemeral class of records in memory, Postgres and
  MariaDB
status: Done
assignee: []
created_date: '2026-11-25T18:05:00Z'
updated_date: '2026-11-26T18:28:00Z'
labels:
  - go
dependencies:
  - TASK-428
  - TASK-429
documentation:
  - >-
    backlog/docs/doc-7 -
    kv-durable-store-cache-and-reliable-pub-sub-over-Postgres-and-MariaDB-plan-for-review.md
priority: medium
ordinal: 444000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
doc-7, Proposal 1 and 2. kv serves two needs through one store: records whose loss or duplication is a security defect (single-use values, sessions, registrations), and caches and mirrors where a lost entry costs a refetch. Plan: Durability (Durable, Ephemeral) and DurabilityOf(store), passed through by wrappers; an ephemeral twin of the memory store; kv_cache in Postgres (UNLOGGED, asynchronous commit for transactions that touch only it) and in MariaDB (InnoDB: the promise is kept by semantics, not speed). A consumer that needs durability refuses an ephemeral store at start. The class of a kind of record is the host's choice. Sealed stores name the class in the purpose, so that a sealed durable record cannot be moved into the cache table or back.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 DurabilityOf reports the class of memory, Postgres and MariaDB stores and passes through NewSealed
- [x] #2 The ephemeral stores pass the contract suite; on Postgres the table is unlogged and its writes do not wait for the WAL flush, shown by a test
- [x] #3 A sealed record of one class is refused when found in the table of the other
- [x] #4 What MariaDB's ephemeral class costs against the durable one is measured and recorded, not assumed
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
2026-11-26, on feat/kv-durability. kv/durability.go (Durability, Classed, DurabilityOf, ErrEphemeralEvent); memory with WithMemoryEphemeral; the sealed store passes the class on and, over an ephemeral store, extends its purpose so that the class is in the derived key and the associated data (durable records unchanged). Postgres: step 4 kv_cache UNLOGGED with the indexes of kv, WithEphemeral, statements name the records' table as @kv and run on the store's table, each write of the ephemeral store is sent with SET LOCAL synchronous_commit = off in one batch (a transaction's setting, so that it holds behind a pooler), Tx sets it after BEGIN. MariaDB: step 4 kv_cache as InnoDB, WithEphemeral, the same statements over tabled handles. An ephemeral store refuses events in every backend: one class per transaction. A store that does not say its class counts as durable, as before the classes; chosen over 'ephemeral unless said' because every existing store and wrapper is durable. AC 2: relpersistence of kv_cache is u, of kv p; a write and a transaction of the ephemeral store run with synchronous_commit off, of the durable store on (asked through the write path itself). AC 3: a sealed record moved between the classes fails with ErrIntegrity under the same and under another key. AC 4, one writer, 512 bytes, 2000 writes, databases in containers with their data in memory, on a laptop: Postgres 18 durable 0.75 ms, ephemeral 0.34 ms; MariaDB 10.11 durable 0.71 ms, ephemeral 0.47 ms; MariaDB 12.3 durable 0.45 ms, ephemeral 0.49 ms: no difference on MariaDB beyond the noise between runs. just kv-mariadb-test prints the numbers. Verified: kv, Postgres (-race) and just kv-mariadb-test with the Galera cluster pass, the ephemeral contract also through three nodes; just lint exits 0.

2026-11-26, released at the maintainer's word: go/kv v0.11.0, then go/kv/postgres v0.12.0 and go/kv/mariadb v0.3.0 requiring it; the hosts pinned. just check in go/ passed on the branch (after two comments revive asked for, which just lint does not run: it is go vet and staticcheck only) and on the pinned state.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
kv has two classes of records. DurabilityOf says which a store is of; ephemeral stores (WithEphemeral, WithMemoryEphemeral) keep their records in kv_cache, pass the store's contract, run transactions over their records and publish no events. Postgres writes them to an unlogged table without waiting for the flush, about twice as fast in the measurement; MariaDB writes them like durable ones. A sealed record of one class does not open in the other. Released as go/kv v0.11.0, go/kv/postgres v0.12.0, go/kv/mariadb v0.3.0.
<!-- SECTION:FINAL_SUMMARY:END -->
