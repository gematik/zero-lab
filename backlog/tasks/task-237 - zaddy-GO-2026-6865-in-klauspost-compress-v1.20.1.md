---
id: TASK-237
title: 'zaddy: GO-2026-6865 in klauspost/compress v1.20.1'
status: In Progress
assignee: []
created_date: '2026-11-06T17:20:00Z'
updated_date: '2026-11-06T17:49:00Z'
labels:
  - go
  - security
dependencies: []
priority: high
ordinal: 253000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
govulncheck in just check (found on spec/go-pki-validation, zaddy untouched there): zaddy's code reaches GO-2026-6865 in github.com/klauspost/compress v1.20.1, fixed in v1.20.2. A patch bump of an existing indirect dependency.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 zaddy requires klauspost/compress >= v1.20.2 and just vuln is clean
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Patch bump of github.com/klauspost/compress to v1.20.2 in zaddy (go get, go mod tidy), on spec/go-pki-validation so the branch's just check is clean; vuln, mod-check, tests for zaddy.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
On spec/go-pki-validation (8d5b7c14): zaddy requires klauspost/compress v1.20.2; govulncheck clean for zaddy, go mod tidy -diff and verify pass. Only zaddy carries the module.
<!-- SECTION:NOTES:END -->
