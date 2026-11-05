---
id: TASK-179
title: 'bff, pep: session cookies without Secure in production'
status: Done
assignee: []
created_date: '2026-11-02T15:42:00Z'
updated_date: '2026-11-02T23:09:00Z'
labels:
  - go
  - security
dependencies: []
priority: high
ordinal: 189000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
go/bff sets Secure and __Host- only with Config.ProductionGradeCookie, which neither cmd/zero-bff nor cmd/zero-bff-pdp ever sets, so both always send the session cookie without them. go/pep's PEP_INSECURE_COOKIE=true has no production refusal. Found by gosec G124 (TASK-86).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Secure and __Host- are the default in both, the insecure mode is refused in production, and the nolint lines naming this task are gone
<!-- AC:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Fixed with requirement-named tests in the consolidation.
<!-- SECTION:FINAL_SUMMARY:END -->
