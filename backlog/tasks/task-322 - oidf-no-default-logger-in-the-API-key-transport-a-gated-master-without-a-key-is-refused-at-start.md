---
id: TASK-322
title: >-
  oidf: no default logger in the API key transport; a gated master without a key
  is refused at start
status: Done
assignee: []
created_date: '2026-11-15T06:17:00Z'
updated_date: '2026-11-15T11:13:00Z'
labels:
  - oidf
  - go
dependencies: []
ordinal: 337000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
AddAPIKeyTransport (go/oidf/api_key.go:53) writes through the default slog on every request to a gated host without an API key, against go/docs/design.md §2 (a library logs only through the logger it was given) and servers.md rule 14. Rule 17 points to the better fix: a relying party whose master is under the gated development domain and has no API key is refused at start. Found by the review of TASK-315 steps 4 and 4b.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 oidf writes nothing through the default logger; a gated master without an API key is refused at construction, with a test
<!-- AC:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
No default logger in oidf; a gated development master without an API key is refused at construction (ErrAPIKeyRequired), before any request. Merged at d8f24089.
<!-- SECTION:FINAL_SUMMARY:END -->
