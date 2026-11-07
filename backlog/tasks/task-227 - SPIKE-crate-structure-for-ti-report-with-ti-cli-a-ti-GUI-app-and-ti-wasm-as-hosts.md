---
id: TASK-227
title: >-
  SPIKE: crate structure for ti-report with ti-cli, a ti GUI app and ti-wasm as
  hosts
status: Done
assignee: []
created_date: '2026-11-06T06:54:00Z'
updated_date: '2026-11-07T16:03:00Z'
labels:
  - ti-report
  - architecture
  - spike
dependencies: []
references:
  - rust/docs/design.md
  - docs/architecture.md
priority: medium
ordinal: 234000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
ti-report builds the JSON reports (certificate description, TSL findings) that ti-cli prints and ti-wasm hands to JavaScript; it is its own crate so both hosts produce the same reports against ti-cli/schemas, without putting presentation into ti-pki. A third host is coming: a ti GUI app. With three hosts the split between engines, report/presentation and hosts may need another structure (one report crate for all TI functions, reports beside each engine, or a shared host layer). Maintainer, 2026-11-06: spike before refactoring.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 the hosts' needs are listed (ti-cli, ti GUI app, ti-wasm): which reports, schemas, I/O and platform each brings
- [x] #2 two or three structures sketched with their crate graph and cost; one recommended, with the refactoring as its own tasks
<!-- AC:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Hosts: ti-cli (terminal, files, ureq), ti-wasm (browser, JS fetch, no blocking, no SystemTime), Tauri app (async commands, main thread must not block, IPC boundary, own dependency tree). Structures weighed: one report crate for all TI functions; reports beside each engine with ti-cli as lib+bin; a shared native host library. Chosen (decision-15): read-only projections beside each engine as a model module (ti_pki::model) with Serialize behind an optional serde feature, logic into the engine, ti-client as host library under ti-cli and ti-app, ti-app in its own workspace. Refactoring: TASK-243 to TASK-253.
<!-- SECTION:FINAL_SUMMARY:END -->
