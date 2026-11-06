---
id: TASK-229
title: 'zero-epa: TLS verification skipped when no cert pool is set'
status: To Do
assignee: []
created_date: '2026-11-06T07:36:00Z'
labels:
  - epa
  - go
  - security
dependencies: []
priority: high
ordinal: 240000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Found while planning TASK-97: go/epa/session_manager.go sets InsecureSkipVerify whenever CertPool is nil; zero-epa proxy never sets one and zero-epa probe skips unconditionally. Related: TASK-180, TASK-98.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 no zero-epa path connects to an ePA endpoint without verifying its certificate
<!-- AC:END -->
