---
id: TASK-433
title: 'kv: NewSealedFeed, and purposes per class'
status: In Progress
assignee: []
created_date: '2026-11-25T18:05:00Z'
updated_date: '2026-11-26T18:42:00Z'
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
- [x] #1 An event moved to another topic or number, or replayed from another purpose, is refused when followed
- [x] #2 Marker and Resealer (Others, Reseal, Rename, SealedByKeys) pass the contract suite over both record tables in Postgres and MariaDB
- [x] #3 The database and its notification queue hold no payload in the clear: shown by a test that reads the tables
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
2026-11-26, on feat/kv-sealed-feed. kv/sealed_feed.go: eventSealer (format version | len(key ID) | key ID | salt | nonce | ciphertext and tag; HKDF label of its own, so that the keys of events and of records differ under one ring; associated data version, key ID, purpose, topic, number, each length-prefixed), NewSealedFeed, WithSealedEvents, the sealed store as Feed, sealedTx.Publish (ErrSealedEvent is gone). To bind an event to its number the backends offer PublishNumbered (kv.NumberedFeed, kv.NumberedTx): the payload is made by a function of the number inside the publishing transaction; memory, Postgres and MariaDB implement it and their plain Publish goes through it. A follower leaves out an event that does not open and logs topic and number; the missing number is the signal. AC 1, kvtest.SealedFeed, through the feed below as someone with write access to the database would: an event copied to another topic and to another number of its topic, another purpose, another key, an altered event, one never sealed and an empty one are not delivered, the events in their places are; an event sealed under a key of before opens while the ring holds it; passes in memory, Postgres, MariaDB and through three Galera nodes. AC 2, kvtest.Resealer over the durable and the ephemeral table in Postgres and MariaDB: SealedByKeys, SealedBy, CountOthers, Others page by page, Reseal once, Rename once. AC 3: after a sealed Set in each class and a sealed transaction with Publish, no row of kv, kv_cache or kv_feed holds the secret (position of the bytes in the column), and the notification's payload is the topic. Verified: kv (-race), Postgres 18 (-race), just kv-mariadb-test; just lint golangci modernize exit 0.
<!-- SECTION:NOTES:END -->
