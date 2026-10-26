---
id: TASK-120.4
title: 'ti-pki-helper: pki/1 (load, verify, verify-signature)'
status: To Do
assignee: []
created_date: '2026-10-20 14:07'
updated_date: '2026-10-20 19:57'
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
- [ ] #2 both trust modes tested
- [ ] #3 container layout documented and tested with separate state, cache and key-file mounts
- [ ] #4 dependency check in just check
<!-- AC:END -->
