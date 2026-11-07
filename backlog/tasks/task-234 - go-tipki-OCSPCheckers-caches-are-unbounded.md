---
id: TASK-234
title: 'go/tipki: OCSPChecker''s caches are unbounded'
status: In Progress
assignee: []
created_date: '2026-11-06T14:30:00Z'
updated_date: '2026-11-07T10:40:00Z'
labels:
  - go
  - security
dependencies: []
priority: low
ordinal: 250000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Found in TASK-98.2 review: tipki.OCSPChecker's result cache and its map of paused responders shrink only when an entry is looked up again, so a long-running host that meets many certificates grows them without limit. titls uses it as the ti responder. Bound both (size, expired entries dropped on insert), with tests.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 both caches have a size bound and drop expired entries on insert, with a test
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
2026-11-07, go-batch b52f7c6d: putBounded drops expired entries on every insert and, at the bound, the entry ending first; OCSPCacheLimit 4096 results, OCSPRestingLimit 1024 responders. Test TestOCSPCachesAreBoundedAndDropExpiredEntriesOnInsert.
<!-- SECTION:NOTES:END -->
