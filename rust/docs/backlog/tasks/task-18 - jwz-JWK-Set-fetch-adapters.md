---
id: TASK-18
title: 'jwz: JWK Set fetch adapters'
status: To Do
assignee: []
created_date: '2026-10-10 05:58'
labels:
  - jwz
dependencies: []
priority: medium
ordinal: 18000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
jwz parses JWK Sets but never fetches: the caller brings the keys. Adapters for jwks_uri with caching and rotation (kid miss triggers one refetch), over ureq, reqwest and browser fetch, as crates or features outside jwz's core.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Fetch, cache with max-age, refetch once on unknown kid, rate-limited
- [ ] #2 No network code in jwz itself; jwz-backends still passes
<!-- AC:END -->
