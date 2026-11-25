---
id: TASK-434
title: 'kv: a guide for hosts'
status: To Do
assignee: []
created_date: '2026-11-25T18:05:00Z'
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
- [ ] #1 go/kv has a guide for hosts covering each row of doc-7's table, linked from AGENTS.md's row
- [ ] #2 Every statement of the guide about a backend is one a contract test proves, and names it
<!-- AC:END -->
