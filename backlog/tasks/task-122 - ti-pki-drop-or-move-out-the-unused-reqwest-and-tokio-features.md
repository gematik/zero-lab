---
id: TASK-122
title: 'ti-pki: drop or move out the unused reqwest and tokio features'
status: Done
assignee: []
created_date: 2026-10-20 17:46
updated_date: '2026-11-01T13:08:00Z'
labels:
  - ti-pki
  - dependencies
milestone: m-0
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
- [x] #1 decided with the maintainer: removed, or moved into adapter crates
- [x] #2 features, wasm32 and the docs (rust/docs/development.md, rust/docs/design.md) match the decision
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Decided with the maintainer: removed, not moved. Both were thin adapters on top of load::Transport and Reloader, which stay; a Rust server brings its own in its crate. The examples ocsp and validate needed reqwest and are deleted, since ti pki verify does what they did and a replacement transport would have made ti-pki's dev-dependencies pick a TLS stack. supply-chain/config.toml: only the 44 exemptions of crates gone from Cargo.lock are removed; a full cargo vet prune also refreshed imports.lock and dropped unrelated exemptions, which is not this change.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
ti-pki no longer has the features reqwest and tokio; tracing, tokio, reqwest and hyper are gone from the workspace's lock file. The host implements load::Transport and calls Reloader::tick. Docs, wasm32 and the release notes match. just check green.
<!-- SECTION:FINAL_SUMMARY:END -->
