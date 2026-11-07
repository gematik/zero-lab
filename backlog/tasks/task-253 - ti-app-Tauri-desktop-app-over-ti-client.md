---
id: TASK-253
title: 'ti-app: Tauri desktop app over ti-client'
status: To Do
assignee: []
created_date: '2026-11-07T15:53:00Z'
updated_date: '2026-11-07T15:53:00Z'
labels:
  - ti-app
  - architecture
  - deps
  - security
dependencies:
  - TASK-250
references:
  - docs/architecture.md
  - docs/conventions/dependencies.md
priority: low
type: feature
ordinal: 269000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Decision-15: the GUI is a Tauri app, ti-app, over ti-client. Tauri needs its own crate (tauri-build in build.rs, configuration, assets, bundler) and brings several hundred crates, which would enter the workspace's Cargo.lock and its vet, deny and unsafe audits; so ti-app is its own workspace with its own Cargo.lock. A synchronous Tauri command runs on the main thread and would freeze the window, so commands are async and run ti-client in spawn_blocking; ti-client's futures need not be Send. The UI's own state (selection, progress) is its view model in the frontend; the Rust side hands it the engines' model types, serialized.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Tauri and the frontend toolchain are evaluated and approved by the maintainer before they are added (dependencies.md), including unsafe and the transitive count
- [ ] #2 ti-app is a workspace of its own; rust/Cargo.lock and the workspace audits are unchanged
- [ ] #3 every command is async and calls ti-client through spawn_blocking; no command blocks the main thread
- [ ] #4 PINs, PKCS#12 passwords and comfort IDs never cross the IPC boundary; the IPC capabilities and the CSP allow only what the commands need
- [ ] #5 TypeScript types are generated from ti-cli's JSON schemas; Linux build prerequisites (webkit2gtk) are documented
<!-- AC:END -->
