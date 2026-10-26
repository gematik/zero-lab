---
id: TASK-122
title: 'ti-pki: drop or move out the unused reqwest and tokio features'
status: To Do
assignee: []
created_date: '2026-10-20 17:46'
labels:
  - ti-pki
  - dependencies
dependencies: []
priority: low
ordinal: 133000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
ti-pki has eight features; reqwest (a transport over a caller's reqwest::Client) and tokio (background reloader, SIGHUP, admin trigger) have no consumer in the repository: the servers are Go and reach Rust through the ti helpers (TASK-120), which use os. They cost a third of the feature-powerset runs in just check-full (40 of 78 are ti-pki) and keep reqwest, tokio and tracing in ti-pki's optional tree. rust/docs/development.md already plans to move them into their own crates before ti-pki 1.0. Decide: remove them now (a breaking change of a 0.x crate without consumers) or move them into adapter crates when a Rust server needs them.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 decided with the maintainer: removed, or moved into adapter crates
- [ ] #2 features, wasm32 and the docs (rust/docs/development.md, rust/docs/design.md) match the decision
<!-- AC:END -->
