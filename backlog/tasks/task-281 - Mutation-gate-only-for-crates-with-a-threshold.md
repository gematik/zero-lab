---
id: TASK-281
title: Mutation gate only for crates with a threshold
status: Done
assignee: []
created_date: '2026-11-08T19:08:00Z'
updated_date: '2026-11-08T19:09:00Z'
labels:
  - rust
  - release
  - testing
dependencies: []
priority: high
ordinal: 297000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The release gate (TASK-53) refused every released crate without a recorded score, also ti-cli and the other crates without a threshold, where a score decides nothing: nothing can fall below a threshold that is not there. A ti-cli score would take hours (its tests run the binary). Maintainer (2026-11-08): a crate with a threshold (the security crates) still needs a current score at release; one without is not gated, and can be measured by hand with just mutants.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 just mutants-gate passes a crate without a threshold and says so; a crate with one still needs a current score at or above it; tested
- [x] #2 docs/design/testing.md and rust/docs/development.md say so
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
judge() decides per crate: no threshold passes ('not gated'); a threshold needs a score of the current code (affecting, TASK-280) that reaches it. Tested in scripts/test_mutation.py (Gate). docs/design/testing.md's table row and rust/docs/development.md updated.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
The mutation gate holds only crates with a threshold to a score: those still need a score of their current code that reaches it; a crate without one (ti-cli, ti-client, …) passes as 'not gated' and is measured by hand with just mutants when wanted. Documented in docs/design/testing.md and rust/docs/development.md; tested in scripts/test_mutation.py.
<!-- SECTION:FINAL_SUMMARY:END -->
