---
id: TASK-134
title: 'ti-cli store/files: unused import and mut on Windows builds'
status: Done
assignee: []
created_date: 2026-10-22 19:24
updated_date: '2026-10-26T14:54:00Z'
labels:
  - ti-cli
  - windows
milestone: m-0
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
- [x] #1 The Windows cross build of ti-cli has no warnings
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Shown by the new cli-check (TASK-135). File comes from fs:: in the one Unix use; sync_dir is one function with cfg!(unix), so clippy's unnecessary_wraps does not fire on a Windows-only stub returning Ok(()); make_dir's mut is allowed off Unix, where the builder gets no mode.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
store/files.rs builds without warnings for x86_64-pc-windows-gnu: File through fs::, one sync_dir with cfg!(unix), make_dir's mut allowed off Unix. Verified by just cli-check (clippy -D warnings in the cross containers) and just check.
<!-- SECTION:FINAL_SUMMARY:END -->
