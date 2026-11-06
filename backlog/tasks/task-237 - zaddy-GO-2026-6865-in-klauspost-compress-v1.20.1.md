---
id: TASK-237
title: 'zaddy: GO-2026-6865 in klauspost/compress v1.20.1'
status: To Do
assignee: []
created_date: '2026-11-06T17:20:00Z'
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
- [ ] #1 zaddy requires klauspost/compress >= v1.20.2 and just vuln is clean
<!-- AC:END -->
