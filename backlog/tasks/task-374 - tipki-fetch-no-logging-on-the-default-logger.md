---
id: TASK-374
title: 'tipki/fetch: no logging on the default logger'
status: To Do
assignee: []
created_date: '2026-11-17T06:45:00Z'
labels:
  - tipki
  - go
dependencies: []
priority: low
ordinal: 389000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
tipki/fetch logs through the global slog (found during TASK-289). go/docs/design.md §2: a library logs to the Config.Logger the host hands it, nil logs nothing; the default logger is the host's. idpd (TASK-338) and bundlefile follow this.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 tipki/fetch takes a *slog.Logger in its configuration, nil discards, and no call reaches slog.Default
<!-- AC:END -->
