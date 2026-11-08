---
id: TASK-264
title: 'ti-pki: clippy for --no-default-features --features load'
status: To Do
assignee: []
created_date: '2026-11-08T06:34:00Z'
labels:
  - rust
dependencies: []
ordinal: 280000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
cargo clippy -p ti-pki --all-targets --no-default-features --features load fails on dead code in older tests, and no recipe runs that feature combination. Found during TASK-250.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 the combination passes clippy with -D warnings
- [ ] #2 just check runs it
<!-- AC:END -->
