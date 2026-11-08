---
id: TASK-263
title: 'ti-client: one max-age parser for the transports'
status: In Progress
assignee: []
created_date: '2026-11-08T06:34:00Z'
updated_date: '2026-11-08T09:27:00Z'
labels:
  - rust
dependencies: []
ordinal: 279000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
ti-client's transports parse Cache-Control max-age themselves although ti_cache::CacheControl exists. Found during TASK-249.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 the transports use ti_cache's parser; no second max-age parser in ti-client
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Both ti-client transports read Cache-Control with ti_cache::CacheControl. no-cache and doubtful values now make a response stale (zero freshness) instead of leaving its lifetime unstated.
<!-- SECTION:NOTES:END -->
