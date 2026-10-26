---
id: TASK-134
title: 'ti-cli store/files: unused import and mut on Windows builds'
status: To Do
assignee: []
created_date: '2026-10-22 19:24'
labels:
  - ti-cli
  - windows
dependencies: []
priority: low
ordinal: 145000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The x86_64-pc-windows-gnu release build warns: unused import File (store/files.rs:33) and unneeded mut on the DirBuilder (store/files.rs:391); both are only used by cfg(unix) code. just check builds no Windows target, so it does not see them.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The Windows cross build of ti-cli has no warnings
<!-- AC:END -->
