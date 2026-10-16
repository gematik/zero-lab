---
id: TASK-113
title: 'spec/store: index for expiry-range queries'
status: To Do
assignee: []
created_date: '2026-10-16 05:16'
labels:
  - spec
  - store
dependencies: []
priority: low
ordinal: 119000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
query with an expiry range and no tag filter walks the namespace in name order on the SQLite backend (schema.sql has only a partial index on expires_at, used by cleanup), so its cost grows with the namespace, against STORE-018's indexed. Measured in TASK-103.4: 16 ms for a 500-record range among 100,000 records (release). Decide whether STORE-018 exempts range-only queries or a level-2 expand migration adds an index on (ns, expires_at), with the sort it implies.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 STORE-018 and schema.sql agree on what an expiry-range query costs
<!-- AC:END -->
