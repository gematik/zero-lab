---
id: TASK-333
title: 'ti-pkcs12: the decode fuzz target fails on its own work-budget-total seed'
status: Done
assignee: []
created_date: '2026-11-15T09:56:00Z'
updated_date: '2026-11-16T20:33:00Z'
labels:
  - rust
  - pkcs12
  - fuzz
dependencies: []
ordinal: 348000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Found while fixing TASK-329 (2026-11-15): just fuzz-ti-pkcs12 stops at once on main, on the committed corpus seed work-budget-total. The target asserts that LimitExceeded reports a single count above the limit, but that seed exceeds the work budget with the sum of several counts, so the assertion is wrong, or the error does not say what exceeded. A fuzz target that fails on its own seeds proves nothing (testing.md, fuzzing).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 just fuzz-ti-pkcs12 runs its whole seed corpus green; the assertion matches what LimitExceeded reports for a budget exceeded by a sum
<!-- AC:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
The decode target asserts what LimitExceeded reports for a budget exceeded by a sum (a known derivation and a count of at least 1); just fuzz-ti-pkcs12 runs both targets over their whole seed corpus green.
<!-- SECTION:FINAL_SUMMARY:END -->
