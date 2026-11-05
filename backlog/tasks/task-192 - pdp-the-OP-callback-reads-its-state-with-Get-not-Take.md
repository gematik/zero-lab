---
id: TASK-192
title: 'pdp: the OP callback reads its state with Get, not Take'
status: In Progress
assignee: []
created_date: '2026-11-02T22:59:00Z'
updated_date: '2026-11-05T18:30:00Z'
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
- [x] #1 The state of an OP callback is single use, with a test
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
The OP callback's state is single use: Take on the index, and the saved session no longer carries it, or saving would index it again. A request with neither code nor error does not consume it.
<!-- SECTION:NOTES:END -->
