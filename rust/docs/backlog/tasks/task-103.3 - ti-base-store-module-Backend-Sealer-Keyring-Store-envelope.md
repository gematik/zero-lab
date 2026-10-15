---
id: TASK-103.3
title: 'ti-store: store module (Backend, Sealer, Keyring, Store, envelope)'
status: To Do
assignee: []
created_date: '2026-10-15 17:45'
updated_date: '2026-10-15 18:57'
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
Sans I/O core of spec/store in ti_store::store: traits without Send/Sync bounds, envelope parser and builder, derivation, memory backend, key-file wrapper. Crypto from existing workspace deps (aes-gcm, hkdf, hmac, sha2, zeroize, subtle), behind a feature so cache-only users do not pay for it. No I/O; builds for wasm32.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 passes the spec/store vectors in tests named after the STORE rules
- [ ] #2 fuzz targets for the envelope and keyring-file parsers
- [ ] #3 no I/O in ti-store; builds for wasm32-unknown-unknown; just core-deps and just wasm32 pass
<!-- AC:END -->
