---
id: TASK-202
title: >-
  epa portal: compact status on the first page, refreshed every 5 seconds behind
  a server-side guard
status: Done
assignee: []
created_date: '2026-11-03T16:49:00Z'
updated_date: '2026-11-05T19:19:00Z'
labels:
  - epa
dependencies: []
ordinal: 209000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The first page's status takes much room and loads once. Show TI services and all proxies in two compact columns, name the providers IBM, RISE and EY, and refresh the proxies every 5 seconds. Polling must not reach the TI services or the IDP at that rate.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Callers of a proxy's status within 5 seconds share one result
- [x] #2 A provider whose status failed is not tried again for 60 seconds; its last error is reported meanwhile
- [x] #3 A healthy provider is checked again once the shared result has expired
- [x] #4 The first page shows TI services and all proxies in two columns, each proxy as soon as it answers, with the providers named IBM, RISE and EY
- [x] #5 The proxies refresh every 5 seconds, never overlapping and not while the tab is hidden; TI services load once
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
statusGuard in go/epa/status_guard.go sits between GET /status and the providers. Checked with stub API in Chrome Canary and a node harness for the refresh rules; not yet against live providers. The guard covers the status endpoint only.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
The epa portal's first page shows a compact status, refreshed every 5 seconds behind a server-side guard.
<!-- SECTION:FINAL_SUMMARY:END -->
