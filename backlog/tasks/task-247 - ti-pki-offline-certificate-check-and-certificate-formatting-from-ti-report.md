---
id: TASK-247
title: 'ti-pki: offline certificate check and certificate formatting from ti-report'
status: To Do
assignee: []
created_date: '2026-11-07T15:53:00Z'
updated_date: '2026-11-07T16:03:00Z'
labels:
  - ti-pki
  - ti-report
  - architecture
dependencies: []
references:
  - docs/architecture.md
priority: medium
type: task
ordinal: 263000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Decision-15: ti-report goes; its projections become ti_pki::model (TASK-248), and the logic in it moves to the crate it belongs to. ti-report/src/check.rs (CheckContext) is a use case of its own: it loads trust material (a supplied roots.json only if the TSL verifies with it, else the embedded roots, with a warning), selects the profile for the certificate (or checks the chain only, with a warning) and validates with revocation disabled. ti-wasm uses it directly (ti-wasm/src/api.rs), so it cannot live in a host library. fingerprint and pem in ti-report/src/lib.rs format a certificate.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 ti-pki offers the offline check as API returning Rust types: the source of the roots and its warning, the profile chosen and why, and the ValidationResult
- [ ] #2 the check is tested in ti-pki without JSON, under the requirement IDs the ti-report tests carry
- [ ] #3 Certificate has methods for the SHA-256 fingerprint and PEM; ti-report and ti-cli call them
<!-- AC:END -->
