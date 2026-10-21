---
id: TASK-132
title: 'oidf: retracted dependency gabriel-vasile/mimetype v1.4.15'
status: To Do
assignee: []
created_date: '2026-10-21 08:43'
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
- [ ] #1 no go.mod in the Go workspace requires a retracted version; govulncheck and go list -m -retracted are clean for oidf
<!-- AC:END -->
