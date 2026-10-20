---
id: TASK-103.8
title: 'spec/store: Go/Rust interop matrix on one store file'
status: Done
assignee: []
created_date: '2026-10-15 17:45'
updated_date: '2026-10-20 10:10'
labels:
  - spec
  - tests
dependencies:
  - TASK-103.4
  - TASK-103.7
parent_task_id: TASK-103
priority: medium
ordinal: 109000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
interop/run.sh: Go writes state.db and Rust reads it, the reverse, and a concurrent take race across processes on one file; results in interop/matrix.md.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 round trips both ways pass
- [x] #2 exactly one of two cross-language takes succeeds
<!-- AC:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
spec/store/interop/run.sh runs the Go and Rust implementations on one profile's files, SQLite and files backend: round trips both ways (sealed get, query by one and two tags, a sealed record without expiry, a plain cache record, a take by the other language) and 20 rounds of 8 Go and 8 Rust processes taking one record at once with exactly one winner each; 32 of 32 cells pass, both languages win races. Drivers: go/sqlitestore/cmd/store-interop and rust/ti-cli/examples/store-interop.rs (ti-cli's store module is public, doc(hidden), for it). Result in spec/store/interop/matrix.md; CONFORMANCE.md describes it.
<!-- SECTION:FINAL_SUMMARY:END -->
