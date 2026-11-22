---
id: TASK-374
title: 'tipki/fetch: no logging on the default logger'
status: Done
assignee: []
created_date: '2026-11-17T06:45:00Z'
updated_date: '2026-11-22 15:07'
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
- [x] #1 tipki/fetch takes a *slog.Logger in its configuration, nil discards, and no call reaches slog.Default
<!-- AC:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
tipki/fetch logs to a logger the host hands it with fetch.WithLogger and to nothing without one (go/docs/design.md section 2), never to slog's default. idpd passes its ClientConfig.Logger through idpd.WithTrustLogger, zero-epa its default logger. Test: TestGoDesign2_TheTrustLogsToTheHostsLoggerOnly.
<!-- SECTION:FINAL_SUMMARY:END -->
