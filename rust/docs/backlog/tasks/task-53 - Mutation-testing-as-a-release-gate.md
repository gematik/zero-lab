---
id: TASK-53
title: Mutation testing as a release gate
status: To Do
assignee: []
created_date: '2026-10-14 20:43'
labels:
  - tests
  - release
dependencies: []
references:
  - rust/docs/design.md
priority: medium
ordinal: 51000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
cargo-mutants runs by hand (just mutants). A mutation score per crate before a release would make it a gate (Making the sources safe and secure).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 a mutation score per crate recorded before release, a threshold for the security crates, and the release procedure checks it
<!-- AC:END -->
