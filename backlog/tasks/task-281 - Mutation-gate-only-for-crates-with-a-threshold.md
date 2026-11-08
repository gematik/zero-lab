---
id: TASK-281
title: Mutation gate only for crates with a threshold
status: To Do
assignee: []
created_date: '2026-11-08T19:08:00Z'
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
- [ ] #1 just mutants-gate passes a crate without a threshold and says so; a crate with one still needs a current score at or above it; tested
- [ ] #2 docs/design/testing.md and rust/docs/development.md say so
<!-- AC:END -->
