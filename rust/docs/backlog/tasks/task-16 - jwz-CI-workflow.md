---
id: TASK-16
title: 'jwz: CI workflow'
status: To Do
assignee: []
created_date: '2026-10-10 05:58'
labels:
  - jwz
  - ci
dependencies: []
priority: medium
ordinal: 16000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Milestone 1 runs everything through rust/Justfile; there is no GitHub Actions workflow. just check needs none of the design-time tools (stamps carry their results), so CI can run it on stable Rust.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Workflow runs just check and just audit on stable Rust for pull requests touching rust/
- [ ] #2 A stale design-time stamp fails CI (cargo test -p jwz --test stamps)
- [ ] #3 Optional scheduled job runs just fuzz-jwz and just jwz-browser
<!-- AC:END -->
