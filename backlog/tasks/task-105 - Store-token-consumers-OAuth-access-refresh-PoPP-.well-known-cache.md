---
id: TASK-105
title: 'Store: token consumers (OAuth access/refresh, PoPP, .well-known cache)'
status: To Do
assignee: []
created_date: '2026-10-15 17:45'
labels:
  - ti-cli
  - go
  - security
dependencies:
  - TASK-103
priority: medium
ordinal: 111000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Persist tokens and discovery documents through the store once TASK-103 lands; supersedes TASK-30's 'no token cache'. Tokens only in sealed namespaces; subject identifiers (KVNR, Telematik-ID) only as blind-index tags.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 tokens survive across ti and zero-epa invocations within a profile
- [ ] #2 no token or subject identifier appears in plain text in state.db
<!-- AC:END -->
