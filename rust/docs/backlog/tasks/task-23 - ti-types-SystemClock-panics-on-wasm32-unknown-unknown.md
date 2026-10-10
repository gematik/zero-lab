---
id: TASK-23
title: 'ti-types: SystemClock panics on wasm32-unknown-unknown'
status: To Do
assignee: []
created_date: '2026-10-10 05:58'
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
- [ ] #1 ti-types' SystemClock unavailable on wasm32-unknown-unknown, or backed by Date.now() through ti-wasm
- [ ] #2 just wasm32 still passes
<!-- AC:END -->
