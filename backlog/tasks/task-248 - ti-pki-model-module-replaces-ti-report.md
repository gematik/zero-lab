---
id: TASK-248
title: 'ti-pki: model module replaces ti-report'
status: In Progress
assignee: []
created_date: '2026-11-07T15:53:00Z'
updated_date: '2026-11-07T20:09:00Z'
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
- [x] #1 ti_pki::model holds the projections as plain types (e.g. model::Certificate, model::Tsl, model::Check), always compiled, mapping only: no I/O, no validation, no clock of their own
- [x] #2 Serialize is derived only with ti-pki's serde feature; ti-pki builds and tests without it
- [x] #3 ti-cli and ti-wasm use ti_pki::model; their JSON output is unchanged (ti-cli/schemas still validate it) or each change is recorded in ReleaseNotes
- [x] #4 ti-report's tests, fuzz target and traceability entries live in ti-pki; the ti-report crate is removed from the workspace, the Justfile and the docs
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
ti_pki::model (always compiled): Certificate (was CertificateInfo; Key, ProfileHint, Admission), Oid (was OidInfo), TypeOid, Finding, CertSummary, rejection_code, validity, Tsl (was TslView; Signature, List, Scheme, PostalAddress, Pointer, Roots, Root, Counts, Provider, Service, Chain, Skipped), Check (was CheckReport; TslState, ProfileUsed, Issue, TrustNode), SCHEMA. Constructors that take offline types (Tsl::new, Check::new, TslState::new) need feature load. Serialize only with the new serde feature (cfg_attr derive; serde stays a normal dependency for roots.json); ti-pki builds, clippies and tests without it (cargo hack powerset depth 2 clean). tsl_view verified the list itself; to keep model mapping only, the verification moved to offline::Tsl::verify (load + brainpool): verified TSL, roots with source and warning, matched CAs, kept CAs with their roots, the chain of every service in accord. model::Check::new(&check, certs, &outcome, now) maps an offline::Check outcome; TrustNode ids compare service certificates instead of a precomputed fingerprint set. ti-cli and ti-wasm (features load, serde) use model and offline; JSON byte for byte unchanged against the build before TASK-247 (47 CLI invocations in json/markdown/text, only wall-clock 'days left' text differs; the ti-wasm API over every fixture, TSL, environment, time and supplied roots). ti-report removed: tests to ti-pki/tests/model.rs and offline.rs and model unit tests (names kept; hex/fingerprint/pem tests as unit tests where the helpers live), fuzz targets describe_certificate, verify_tsl, verify_tsl_roots to ti-pki/fuzz on ti-pki's API (no ti-wasm dependency), just fuzz-ti-pki runs them, fuzz-ti-report gone; Cargo.toml, Justfile (check-changed list, wasm32), docs (design.md, development.md, unsafe-exceptions.md Cores, README), ReleaseNotes (ti-report entries under ti-pki), tsl_signature.rs comment; no mutation threshold existed.
<!-- SECTION:NOTES:END -->
