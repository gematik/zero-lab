---
id: TASK-23
title: 'ti-types: SystemClock panics on wasm32-unknown-unknown'
status: Done
assignee: []
created_date: '2026-10-10 05:58'
updated_date: '2026-10-10 07:50'
labels:
  - ti-types
  - wasm
dependencies: []
priority: low
ordinal: 23000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
std has no clock on wasm32-unknown-unknown: SystemTime::now() panics there. jwz's SystemClock is therefore not offered on that target (found by jwz's browser tests); ti-types' SystemClock still compiles there and would panic if called.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 ti-types' SystemClock unavailable on wasm32-unknown-unknown, or backed by Date.now() through ti-wasm
- [x] #2 just wasm32 still passes
<!-- AC:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
ti-types' SystemClock (and ti-pki's re-exports) are not offered on wasm32-unknown-unknown; using it there is a compile error instead of a panic. just wasm32 checks ti-types with std for wasm32.
<!-- SECTION:FINAL_SUMMARY:END -->
