---
id: TASK-97.3
title: 'TLS verification (c): benchmarks with a budget'
status: Done
assignee: []
created_date: '2026-11-06T07:36:00Z'
updated_date: '2026-11-06T12:16:00Z'
labels:
  - ti-pki
  - tests
dependencies: []
parent_task_id: TASK-97
priority: medium
ordinal: 237000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-97 part (c).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 just tls-bench measures a cold and a cached verification per profile and fails over the budget
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Done on the branch; set Done with the merge.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Merged into main by fast-forward (1f6aa1e6) with TASK-97's branch spec/pki-validation; just check green (820 + 128 tests, deny, vet, stamps).
<!-- SECTION:FINAL_SUMMARY:END -->
