---
id: TASK-254
title: 'rust: scripts/__pycache__ is committed'
status: Done
assignee: []
created_date: '2026-11-07T17:19:00Z'
updated_date: '2026-11-07T18:54:00Z'
labels:
  - rust
  - chore
dependencies: []
priority: low
ordinal: 270000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
rust/scripts/__pycache__/coverage_gaps.cpython-314.pyc and mutation.cpython-314.pyc are tracked in git; compiled bytecode of whichever Python ran last. Found in TASK-238.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 the .pyc files are removed from git and __pycache__ is ignored
<!-- AC:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
rust/scripts/__pycache__ untracked; __pycache__/ in .gitignore.
<!-- SECTION:FINAL_SUMMARY:END -->
