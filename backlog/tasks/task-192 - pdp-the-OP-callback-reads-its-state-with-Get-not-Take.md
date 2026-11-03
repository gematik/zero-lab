---
id: TASK-192
title: 'pdp: the OP callback reads its state with Get, not Take'
status: To Do
assignee: []
created_date: '2026-11-02T22:59:00Z'
labels:
  - go
  - security
dependencies: []
priority: high
ordinal: 202000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
A replay of the callback with another code overwrites the authorization code. Found clearing phase 7 of the consolidation.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The state of an OP callback is single use, with a test
<!-- AC:END -->
