---
id: TASK-433
title: 'kv: NewSealedFeed, and purposes per class'
status: To Do
assignee: []
created_date: '2026-11-25T18:05:00Z'
labels:
  - go
dependencies:
  - TASK-431
  - TASK-432
documentation:
  - >-
    backlog/docs/doc-7 -
    kv-durable-store-cache-and-reliable-pub-sub-over-Postgres-and-MariaDB-plan-for-review.md
priority: medium
ordinal: 446000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
doc-7, Encryption. Feed payloads are sealed with associated data of purpose, topic and the event's number, which the backend has from the topic's counter before it writes the event. Payloads never pass through pg_notify, which carries the number only. Topic names are in the clear like keys; a per-subject topic uses the hashed subject. Re-keying: Marker covers both record tables in every backend; feed events are short-lived, a rotation waits out the retention of the topics sealed under the old key. The walk that takes records along stays with the host.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 An event moved to another topic or number, or replayed from another purpose, is refused when followed
- [ ] #2 Marker and Resealer (Others, Reseal, Rename, SealedByKeys) pass the contract suite over both record tables in Postgres and MariaDB
- [ ] #3 The database and its notification queue hold no payload in the clear: shown by a test that reads the tables
<!-- AC:END -->
