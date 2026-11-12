---
id: TASK-301
title: Rate limiter for servers
status: To Do
assignee: []
created_date: '2026-11-12T21:08:00Z'
labels: []
dependencies: []
ordinal: 317000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
docs/design/servers.md asks servers for rate limits and no module provides one. zeta-pdp-go builds one on kv.Store for its endpoints (its TASK-46, gemSpec_ZETA A_26668-02 with the x-rate-limit headers); a shared one could take its place. Found by zeta-pdp-go, which needs it for the login of insured persons at a sektoral IDP (its TASK-54) or as named.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A decision whether the limiter is a module here; if so, one that counts across replicas on kv.Store
<!-- AC:END -->
