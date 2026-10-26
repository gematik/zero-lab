---
id: TASK-147
title: 'rust: clippy 1.99 lints (assert_is_empty, needless_borrows_for_generic_args)'
status: Done
assignee: []
created_date: '2026-10-26T12:21:00Z'
updated_date: '2026-10-26T14:54:00Z'
labels:
  - rust
  - chore
milestone: m-0
dependencies: []
priority: high
ordinal: 156000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Rust stable 1.99.1 (2026-10-13) adds clippy lints the workspace fails with -D warnings: assert!(x.is_empty()) and debug_assert! of the same in tests and code (assert_is_empty, assert_is_not_empty), and &closure passed to map_err (needless_borrows_for_generic_args). Found by the new cli-check (TASK-135), whose cross containers had 1.99 while the host was on 1.98.1; just check breaks on every machine that updates stable.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 just check and check-full are green on stable 1.99.1
- [x] #2 no lint is allowed or weakened; the sites are rewritten (assert_eq! against an empty value, the closure passed by value)
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Clippy's suggested fix, assert_eq!(x, [] as [T; 0]), hurts readability; the sites keep assert!(x.is_empty()) and pass the value as the failure message, which the lint accepts and which shows the value on failure. Calls are bound to a let first so the message does not repeat them; ti-wasm compares the JSON with json!([]), ti-cli's stdout with "". cache.rs passes the Copy closure by value. The jwz test change made the Kani stamp of src/profile/mod.rs stale: regenerated with just jwz-recheck.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Assert sites rewritten for clippy 1.99 (value as failure message, calls bound first, JSON/str equality where clearer); cache.rs passes the closure by value; Kani stamp of jwz src/profile/mod.rs regenerated (9 harnesses verified). Verified: just check green on rustc 1.99.1, cli-check green for musl and windows-gnu. No lint allowed.
<!-- SECTION:FINAL_SUMMARY:END -->
