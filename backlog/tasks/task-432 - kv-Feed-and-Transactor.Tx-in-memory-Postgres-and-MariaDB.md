---
id: TASK-432
title: 'kv: Feed and Transactor.Tx in memory, Postgres and MariaDB'
status: In Progress
assignee: []
created_date: '2026-11-25T18:05:00Z'
updated_date: '2026-11-26T06:04:00Z'
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
- [x] #1 Feed in memory, Postgres and MariaDB passes one contract suite: order per topic, no event stepped over under concurrent publishers, resume from a cursor, retention
- [x] #2 Tx in the three backends passes one contract suite: all or nothing with Publish, a held Get, a repeated fn, the bound on operations
- [x] #3 On a Galera cluster of three writing nodes concurrent publishers through different nodes yield gapless numbers in commit order, and the root-record pattern serialises transactions of one root; what Get alone does not protect there is stated in the contract
- [x] #4 A missed NOTIFY on Postgres costs latency, not an event: shown by a test
- [x] #5 doc-7's Still open 2 is answered from the tests and the document updated
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
2026-11-25, on feat/kv-feed-tx, nothing committed. Done: kv/feed.go (Cursor, Event, Feed, Transactor, Tx, MaxTxOps, CheckEvent, TxOps), kv/memory_feed.go (the memory store as Feed and Transactor), kvtest.Feed and kvtest.Tx, kv/postgres/feed.go with schema step 3 (kv_topic, kv_feed), Cleanup also removes expired events, WithFeedPoll. Publish takes a retention, which must be positive. Postgres' Tx.Get takes a transaction's advisory lock on the key besides the row lock, so that it also holds a record that is not there. Passing: the contract suites for memory, and the whole Postgres suite with -race against Postgres 18, including an event that arrives without its notification and one that arrives by it. Left: kv/mariadb (steps for kv_topic and kv_feed, Tx, Publish, Follow by polling, the Galera tests through different nodes and what Get does not protect there), the sealed store as Transactor, the hosts' build, lint, doc-7's Still open 2, ReleaseNotes, AGENTS.md, the full check, release.

2026-11-26, on feat/kv-feed-tx, not committed yet. Added since the last note: kv/mariadb/feed.go (steps 2 and 3, Tx at REPEATABLE READ, Publish, Latest, Follow by looking every second, WithFeedPoll), kv/sealed_tx.go (the sealed store as Transactor; Publish refused with ErrSealedEvent), the feed and transaction contracts for MariaDB and through the Galera nodes. Found with the cluster: (1) 16 publishers of one topic through three nodes: a publisher can get error 1062 on its event because another node's publisher took the number and committed first; treated as a lost transaction and run again; (2) 8 tries were too few (17 to 32 of 160 publishes gave up), 32 tries with pauses up to 64 ms sufficed in 5 runs of 160 and in 4 runs of the suite; (3) a record only read is not protected across nodes: 75 to 93 of 100 pairs of write-skewing transactions both committed, while the counter and the root-record cases of kvtest.Tx pass through three nodes. Verified: memory, Postgres 18 (-race) and MariaDB 10.11 and 12.3 pass the contract suites; the Galera suite passed four times with -race; just lint clean for kv, kv/postgres, kv/mariadb; the hosts build. Not built: one class per transaction (TASK-431). doc-7 has the answers under 'Answered with TASK-432'. Open: just check's tidy check needs kv on the remote (push, just sync).
<!-- SECTION:NOTES:END -->
