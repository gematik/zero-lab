---
id: TASK-132
title: 'oidf: retracted dependency gabriel-vasile/mimetype v1.4.15'
status: Done
assignee: []
created_date: 2026-10-21 08:43
updated_date: '2026-11-05T19:19:00Z'
labels:
  - go
  - deps
  - security
dependencies: []
priority: medium
ordinal: 143000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
go get warns that github.com/gabriel-vasile/mimetype v1.4.15, a dependency of go/oidf, is retracted by its author: 'v1.4.15 spends quadratic time for specially crafted CDF files'. Find which dependency pulls it in, update to the latest unretracted version or drop the path that needs it, and check whether the input it inspects can come from outside (a denial of service on hostile files).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 no go.mod in the Go workspace requires a retracted version; govulncheck and go list -m -retracted are clean for oidf
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Only go/epa required it, through validator, not go/oidf: updated to v1.4.16. epa's validate tags use no file or image rules, so the slow path did not look reachable from outside.

TASK-94 then removed validator and with it mimetype, so no go.mod requires it at all.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
No go.mod requires the retracted mimetype: TASK-94 removed validator, its only path in.
<!-- SECTION:FINAL_SUMMARY:END -->
