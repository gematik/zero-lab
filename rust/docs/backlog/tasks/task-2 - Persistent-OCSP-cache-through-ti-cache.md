---
id: TASK-2
title: Persistent OCSP cache through ti-cache
status: To Do
assignee: []
created_date: '2026-10-09 13:55'
labels:
  - ti-pki
  - ti-cli
  - ocsp
dependencies: []
references:
  - ti-pki/src/ocsp.rs
  - ti-cache/src
priority: medium
ordinal: 2000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
OcspChecker caches results in memory only (HashMap, until nextUpdate, capped by the TTL), so every separate ti invocation asks the responder again. Persist results in ti-cache so repeated ti calls benefit. A_23225 suggests 1 h as the caching default (wording still to confirm, see the C_12791 task). Source: Obsidian note C_12791 (follow-ups).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 a second ti pki verify within the TTL answers revocation from the cache, and the report says so
- [ ] #2 unknown results and errors are never cached; nextUpdate and the TTL bound every entry
<!-- AC:END -->
