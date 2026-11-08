---
id: TASK-265
title: 'ti-pki: prove on wasm32 that the loaders need no Send'
status: To Do
assignee: []
created_date: '2026-11-08T06:34:00Z'
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
- [ ] #1 a wasm32 check drives ti-pki's loaders with a loader that is not Send
<!-- AC:END -->
