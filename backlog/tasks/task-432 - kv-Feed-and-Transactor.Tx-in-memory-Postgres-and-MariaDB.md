---
id: TASK-432
title: 'kv: Feed and Transactor.Tx in memory, Postgres and MariaDB'
status: To Do
assignee: []
created_date: '2026-11-25T18:05:00Z'
labels:
  - go
dependencies:
  - TASK-429
  - TASK-430
documentation:
  - >-
    backlog/docs/doc-7 -
    kv-durable-store-cache-and-reliable-pub-sub-over-Postgres-and-MariaDB-plan-for-review.md
priority: medium
ordinal: 445000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
doc-7, Proposal 1 (Feed, Transactions and records that belong together) and 2. Feed: an ordered stream of small events per topic, at least once, resumable from a cursor, retention by time per topic set by the publisher; it replaces Bus plus full rescan for new code. Order comes from a counter row per topic (kv_topic) raised in the transaction that inserts the event into kv_feed, one design in both databases; Postgres notifies transactionally with the number only, MariaDB followers poll. Tx(ctx, func(Tx) error): Get (holds the record), Set, SetIfAbsent, Take, Delete, Publish; no Keys(prefix) (decided 2026-11-25). Contract: fn may run more than once; records are named, not searched; few records; no store calls beside tx; one class per transaction; sealed stores wrap Tx. Patterns for hosts: a root record (Get first, Set last), an index in a related record. Bus and kv/revoked stay for zero-pep-proxy and zaddy. Open before the contract of Tx is final (doc-7, Still open 2): whether writing a read record again makes a decision safe across Galera's writing nodes, and what it costs; answered by the contract tests on a cluster.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Feed in memory, Postgres and MariaDB passes one contract suite: order per topic, no event stepped over under concurrent publishers, resume from a cursor, retention
- [ ] #2 Tx in the three backends passes one contract suite: all or nothing with Publish, a held Get, a repeated fn, the bound on operations
- [ ] #3 On a Galera cluster of three writing nodes concurrent publishers through different nodes yield gapless numbers in commit order, and the root-record pattern serialises transactions of one root; what Get alone does not protect there is stated in the contract
- [ ] #4 A missed NOTIFY on Postgres costs latency, not an event: shown by a test
- [ ] #5 doc-7's Still open 2 is answered from the tests and the document updated
<!-- AC:END -->
