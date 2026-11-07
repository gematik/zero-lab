---
id: TASK-248
title: 'ti-pki: model module replaces ti-report'
status: To Do
assignee: []
created_date: '2026-11-07T15:53:00Z'
updated_date: '2026-11-07T16:03:00Z'
labels:
  - ti-pki
  - ti-report
  - architecture
dependencies:
  - TASK-247
references:
  - docs/architecture.md
  - rust/ti-cli/schemas
priority: medium
type: task
ordinal: 264000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Decision-15: what ti-report holds besides logic are read-only projections of ti-pki's types for the front ends: CertificateInfo, TslView, CertSummary, OidInfo, CheckReport, the SCHEMA version. Serialized, they are the JSON contract between Rust and every front end (ti-cli prints them against ti-cli/schemas, ti-wasm returns them, the Tauri app will generate TypeScript types from them). They live beside the engine as plain Rust types in ti_pki::model, the response model of its use cases; the UI's view model is the frontend's. As decision-13 has it for Go's struct tags, the library declares the shape and the host brings the format: Serialize is derived only under ti-pki's optional serde feature, which ti-cli and ti-wasm enable. Rust's orphan rule keeps a host from implementing Serialize for ti-pki's types, so the derive cannot move into the hosts.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 ti_pki::model holds the projections as plain types (e.g. model::Certificate, model::Tsl, model::Check), always compiled, mapping only: no I/O, no validation, no clock of their own
- [ ] #2 Serialize is derived only with ti-pki's serde feature; ti-pki builds and tests without it
- [ ] #3 ti-cli and ti-wasm use ti_pki::model; their JSON output is unchanged (ti-cli/schemas still validate it) or each change is recorded in ReleaseNotes
- [ ] #4 ti-report's tests, fuzz target and traceability entries live in ti-pki; the ti-report crate is removed from the workspace, the Justfile and the docs
<!-- AC:END -->
