---
id: TASK-434
title: 'kv: a guide for hosts'
status: In Progress
assignee: []
created_date: '2026-11-25T18:05:00Z'
updated_date: '2026-11-26T18:44:00Z'
labels:
  - go
dependencies:
  - TASK-432
  - TASK-433
documentation:
  - >-
    backlog/docs/doc-7 -
    kv-durable-store-cache-and-reliable-pub-sub-over-Postgres-and-MariaDB-plan-for-review.md
priority: low
ordinal: 447000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
doc-7, What a host does. Hosts are built elsewhere; this repository builds the libraries (maintainer, 2026-11-25). The guide tells a host what the libraries leave to it: choosing the backend by the DSN's scheme, running Migrate with admin credentials before a rollout or setting WithMigrate, roles and their rights, the class of each kind of record, topics and retention and the local state built from Follow, keys and the walk that reseals, cleaning, health and metrics; and the two patterns for records that belong together (a root record, an index in a related record) with zeta-authserver-go's store as the worked case. Under docs/conventions/agents.md it is the tool's own guide, not a rule.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 go/kv has a guide for hosts covering each row of doc-7's table, linked from AGENTS.md's row
- [x] #2 Every statement of the guide about a backend is one a contract test proves, and names it
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
2026-11-26, on feat/kv-sealed-feed with TASK-433. go/kv/docs/hosts.md: the modules, choosing the database (DSN, TLS, topologies, the key bound of MariaDB), the schema (the migration job, Open without DDL, contract steps, WithMigrate, the rights of the server's user per database), the two classes, sealing and what happens when the keys change, transactions with the two patterns and a worked login of a new client that evicts another (users, clients, sessions, as in zeta-authserver-go's store; a sketch for a host, not a change to that repository), events, what runs in the background, health and metrics, testing on the memory store, and a table from each statement about a backend to the test that proves it. AC 2 checked by a script: all 34 tests the guide names exist, as do the suites of kvtest, the symbols and the links. Linked from AGENTS.md's row for go/kv; the task table there names the backends. doc-7 says the plan is built and what is left.
<!-- SECTION:NOTES:END -->
