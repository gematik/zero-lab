---
id: TASK-431
title: >-
  kv: Durability and an ephemeral class of records in memory, Postgres and
  MariaDB
status: To Do
assignee: []
created_date: '2026-11-25T18:05:00Z'
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
- [ ] #1 DurabilityOf reports the class of memory, Postgres and MariaDB stores and passes through NewSealed
- [ ] #2 The ephemeral stores pass the contract suite; on Postgres the table is unlogged and its writes do not wait for the WAL flush, shown by a test
- [ ] #3 A sealed record of one class is refused when found in the table of the other
- [ ] #4 What MariaDB's ephemeral class costs against the durable one is measured and recorded, not assumed
<!-- AC:END -->
