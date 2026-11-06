---
id: TASK-97.3
title: 'TLS verification (c): benchmarks with a budget'
status: In Progress
assignee: []
created_date: '2026-11-06T07:36:00Z'
updated_date: '2026-11-06T08:36:00Z'
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
just tls-bench (in check-full) runs ti-tls/examples/tls_bench.rs in a release build: per profile the median of 500 cold verifications (the whole check, no cache) and 20,000 cached handshakes, on the corpus's chains with stapled OCSP. Measured on the maintainer's machine: ti 0.82 ms cold, web 0.53 ms cold, 0.6-0.8 us cached; budgets 5 ms and 10 us. A budget of 1 us made the recipe fail with exit 1.
<!-- SECTION:FINAL_SUMMARY:END -->
