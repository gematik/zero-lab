---
id: TASK-274
title: 'ti-client: Cache-Control from all its field lines'
status: To Do
assignee: []
created_date: '2026-11-08T13:47:00Z'
labels:
  - rust
  - ti-client
dependencies: []
priority: low
ordinal: 290000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Found by TASK-251: http::response_meta reads only the first Cache-Control field line. RFC 9110 §5.3: field lines of one name are one value, joined with ', '; ti_cache::CacheControl expects the joined value (RemoteJwks already joins them). A second line with no-cache or a repeated max-age is ignored today.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 response_meta joins every Cache-Control line before ti_cache::CacheControl reads it, with a test named after RFC 9110 §5.3
<!-- AC:END -->
