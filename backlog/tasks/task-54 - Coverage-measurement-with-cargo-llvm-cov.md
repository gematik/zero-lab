---
id: TASK-54
title: Coverage measurement with cargo llvm-cov
status: Done
assignee: []
created_date: 2026-10-14 20:43
updated_date: '2026-11-05T22:12:00Z'
labels:
  - tests
dependencies: []
references:
  - docs/design/testing.md
  - rust/docs/design.md
priority: medium
ordinal: 52000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
No coverage measurement shows which rules lack tests.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 just coverage producing a per-crate report; uncovered security rules listed as gaps
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
On test/coverage-and-mutation-gate (4294d8f9): just coverage [crate…] with cargo-llvm-cov 0.9.1 (pinned, just tools adds llvm-tools-preview), scripts/coverage_gaps.py lists cited requirements whose code no test runs (heuristic: plain // citation, first instrumented line within 4 lines). jwz: 86.0% of lines, one gap (RFC 7518 Section 6.3.2), filed as a task; ti-types 87.8%.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
just coverage with cargo-llvm-cov 0.9.1, per-crate line coverage and the cited requirements whose code no test runs. Merged into main at 50ea3d15.
<!-- SECTION:FINAL_SUMMARY:END -->
