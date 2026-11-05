---
id: TASK-51
title: 'jwz: tests for the 57 references without a named test'
status: Done
assignee: []
created_date: 2026-10-14 20:42
updated_date: '2026-11-05T22:12:00Z'
labels:
  - jwz
  - tests
dependencies: []
references:
  - docs/design/testing.md
  - rust/jwz/docs/traceability.md
priority: medium
ordinal: 49000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
jwz/docs/traceability.md lists 82 specification references; 57 have no test named after them.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 every reference in the table has a test named after it, or is marked as covered by an indirect test with the reason
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
On worktree-agent-aeab35873d7e289a7 (f19c1e2e). 83 references: 65 with a named test (25 before), 9 cited in a test's doc comment with the reason, 9 whole-document citations traced by their sections. Generator reads test doc comments ((cited)). Citations corrected: RFC 7518 §8.2 -> RFC 8725 §3.4 for invalid curves; RFC 6979 §3.2, RFC 8032 §5.1, RFC 2104 §2 made specific. No bugs found. jwz-recheck reran the browser stamp. Findings filed: TASK-220 (RFC 7517 deviations), TASK-221 (guide.md doc example under default features).
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Every jwz reference has a test: 65 named, 9 cited in a test's doc comment with the reason, 9 whole-document citations traced by their sections. Merged into main at 50ea3d15.
<!-- SECTION:FINAL_SUMMARY:END -->
