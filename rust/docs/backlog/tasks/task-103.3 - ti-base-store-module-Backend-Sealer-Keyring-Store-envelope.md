---
id: TASK-103.3
title: 'ti-base: store module (Backend, Sealer, Keyring, Store, envelope)'
status: To Do
assignee: []
created_date: '2026-10-15 17:45'
labels:
  - ti-cli
  - keys
  - security
  - fuzz
  - wasm
dependencies:
  - TASK-103.1
  - TASK-103.2
references:
  - spec/store/README.md
parent_task_id: TASK-103
priority: medium
ordinal: 104000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Sans I/O core of the store in ti_base::store behind a store feature: traits without Send/Sync bounds, envelope parser and builder, derivation, memory backend, key-file wrapper. Crypto from existing workspace deps (aes-gcm, hkdf, hmac, sha2, zeroize, subtle).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 passes the spec/store vectors in tests named after the STORE rules
- [ ] #2 fuzz targets for the envelope and keyring-file parsers
- [ ] #3 builds no_std + alloc and for wasm32; just core-deps passes
<!-- AC:END -->
