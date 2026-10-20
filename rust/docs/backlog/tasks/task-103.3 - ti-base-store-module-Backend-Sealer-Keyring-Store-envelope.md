---
id: TASK-103.3
title: 'ti-store: store module (Backend, Sealer, Keyring, Store, envelope)'
status: Done
assignee: []
created_date: '2026-10-15 17:45'
updated_date: '2026-10-15 20:41'
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
- [x] #1 passes the spec/store vectors in tests named after the STORE rules
- [x] #2 fuzz targets for the envelope and keyring-file parsers
- [x] #3 no I/O in ti-store; builds for wasm32-unknown-unknown; just core-deps and just wasm32 pass
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Implemented in ti_store::store behind feature store (RustCrypto aes-gcm, hkdf, hmac, sha2, zeroize, getrandom; all existing workspace deps; subtle dropped as unused). Seams: Sealer (keys as functions), async KeyWrapper, Random (OsRandom; FixedRandom behind test-util). Corpus: tests/spec_store.rs (12 tests by rule group) and the example conformance (adapter) share tests/conformance/eval.rs; scenarios of the SQLite backend run on MemoryBackend. Facade tests in tests/store_facade.rs. Fuzz: ti-store/fuzz (record, keyring, record_file, kek_file; round-trip asserts), just fuzz-ti-store; ~24M runs clean. Go verifier against the Rust adapter: 112 passed, 0 failed, 19 unsupported (SQLite/files backends: TASK-103.4).
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
ti_store::store implements spec/store behind feature store with existing workspace crypto; passes the corpus (12 rule-group tests) and the Go verifier (112/131, rest are tool backends of TASK-103.4); facade tests; four fuzz targets; builds for wasm32; just check green.
<!-- SECTION:FINAL_SUMMARY:END -->
