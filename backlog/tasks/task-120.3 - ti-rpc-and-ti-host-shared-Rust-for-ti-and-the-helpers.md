---
id: TASK-120.3
title: 'ti-rpc and ti-host: shared Rust for ti and the helpers'
status: To Do
assignee: []
created_date: 2026-10-20 14:07
updated_date: '2026-11-02T06:16:00Z'
labels:
  - rust
  - parked
dependencies:
  - TASK-120.2
parent_task_id: TASK-120
priority: low
ordinal: 128000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
ti-rpc (internal crate, publish = false): the JSON-lines server loop, handshake, limits, error mapping, tracing at the edge; fuzz targets for the message parser. ti-host (internal crate, publish = false): what ti-cli and the helpers share, moved out of ti-cli so that ti pki verify and ti-pki-helper give the same JSON: the trust session (owned and supplied material, the profile store for cache and TSL state), the pki verify and verify-signature reports, identity loading (PKCS#12, PEM, Konnektor card), the idpd flow glue. Features per capability, so that each helper compiles only what it needs. ti keeps its behaviour and its tests pass unchanged.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 ti-rpc with fuzz targets
- [ ] #2 ti-host extracted, features per capability
- [ ] #3 ti's behaviour and tests unchanged
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
2026-11-02, maintainer: parked. Critical flows go native (decision-10, amendment of 2026-11-02), so the helper does not continue for now. The work stays on the unmerged branches feat/ti-pki-helper and feat/ti-trust-export; spec/ti-rpc, ti-pki-helper, go/tirpc and ti pki trust export live there.
<!-- SECTION:NOTES:END -->
