---
id: TASK-265
title: 'ti-pki: prove on wasm32 that the loaders need no Send'
status: Done
assignee: []
created_date: '2026-11-08T06:34:00Z'
updated_date: '2026-11-08T10:54:00Z'
labels:
  - rust
  - wasm
dependencies: []
ordinal: 281000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
decision-15 makes host traits async without a Send bound; ti-pki's loaders use MaybeSend. A wasm32 test (build or wasm-bindgen-test) that drives them with a loader that is not Send proves it. Found during TASK-252.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 a wasm32 check drives ti-pki's loaders with a loader that is not Send
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
ti-pki/tests/wasm32_not_send.rs compiles only for wasm32: HttpLoader, CachingLoader, FallbackLoader, Reloader and read_back over hosts holding an Rc. just wasm32 type-checks it; natively the same code fails with 19 Send/Sync errors.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
A test that compiles only for wasm32 builds ti-pki's loaders over hosts holding an Rc; just wasm32 type-checks it, natively it fails.
<!-- SECTION:FINAL_SUMMARY:END -->
