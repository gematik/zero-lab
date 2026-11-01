---
id: TASK-120.4
title: 'ti-pki-helper: pki/1 (load, verify, verify-signature)'
status: To Do
assignee: []
created_date: 2026-10-20 14:07
updated_date: '2026-11-01T16:11:00Z'
labels:
  - rust
  - pki
dependencies:
  - TASK-120.3
parent_task_id: TASK-120
priority: low
ordinal: 129000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
rust/helpers/pki, crate and binary ti-pki-helper. Methods load, verify and verify-signature with the schemas of ti pki verify and verify-signature. Two trust modes: owned (downloads TSL and roots, caches them in the profile's cache.db, keeps them hot, does OCSP; network only to the environment's TSL, roots and OCSP endpoints) and supplied (the host passes TSL, roots and optionally OCSP responses; no request at all). For servers and background use, state and cache live in the standard directories and mount cleanly as container volumes: TI_STATE_DIR (for example /var/lib/telematik), TI_CACHE_DIR (/var/cache/telematik), TI_STORE_KEK_PATH from a secret. A check in just check that the helper's dependency tree holds no Konnektor client and nothing its methods do not need.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 answers equal ti pki verify and verify-signature for the same input
- [ ] #2 trust material supplied from a mounted directory only; nothing written to disk; renewal policy owned by the helper, re-fetch signalled to the host
- [ ] #3 Unix-socket listener with peer checks (SO_PEERCRED, pidfd executable on Linux) and the stdio child mode both tested
- [ ] #4 dependency check in just check: no Konnektor client, no store, no profile, no HTTP client
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
2026-11-01 (decision-10): no owned trust mode for servers and no state on disk. The helper verifies trust material the host supplies from a mounted directory (.xml, .sig, .ocsp, roots.json per TASK-166 and TASK-173) and keeps it in memory; it builds OCSP requests and verifies responses the host fetched through its transport (ocsp::request, verify_response). --listen unix:PATH with peer checks is the default for servers, stdio for a child. The dependency check must also prove the helper has no store, no profile and no HTTP client.
<!-- SECTION:NOTES:END -->
