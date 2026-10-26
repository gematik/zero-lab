---
id: TASK-103.1
title: 'spec/store: contract, corpus and generator for the shared sealed store'
status: Done
assignee: []
created_date: '2026-10-15 17:45'
updated_date: '2026-10-15 18:25'
labels:
  - spec
  - keys
  - security
  - tests
dependencies: []
references:
  - spec/README.md
  - docs/interop.md
parent_task_id: TASK-103
priority: medium
ordinal: 102000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Language-neutral contract both CLIs implement byte for byte (docs/interop.md: a concise shared specification). Rule groups STORE-0xx operations, 1xx names and blind-index tags, 2xx HKDF derivation, 3xx AEAD envelope, 4xx keyring file, 5xx SQLite schema, 6xx files backend, 7xx profiles; result codes; security considerations. Layout as spec/README.md, modelled on spec/pkcs12.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 spec/store/README.md has rules STORE-nnn, result codes and security considerations; spec/README.md lists it
- [x] #2 spec/store/tool (Go, stdlib only) regenerates testdata byte for byte and verifies every vector and negative case
- [x] #3 vectors cross-checked once against an independent implementation, recorded in CONFORMANCE.md
- [x] #4 operation scenarios cover TTL, take races, partial batch failure and cursor paging
- [x] #5 implementable on the JVM with JCA only (AES-GCM, HMAC, HKDF over HMAC); the adapter contract is language-neutral so a Kotlin/Java adapter can run the corpus
- [x] #6 a rule forbids private key bytes in the store (docs/design/keys.md rule 1): only handles and references
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
JVM (zeta-cli, ZETA SDK) is a third consumer; its implementation is deferred (separate task) but the spec must not need anything beyond JCA. SQLite on the JVM means sqlite-jdbc (JNI), acceptable for CLIs only (docs/interop.md).

Spec written: 86 rules in sections A-K. Added beyond the plan: K. format levels and migrations (level + min_compatible in a meta table and files meta; forward-only migrations in one BEGIN IMMEDIATE transaction; expand/migrate/contract; cache may be recreated; namespaces never change in place), STORE-097/098 ownership checks (owner = effective user, no symlinks, not group/other writable; checked on the opened file), STORE-024 no private key bytes. Corpus: 132 cases, generated deterministically, verifier tested against wrong answers. Independent check with Node.js node:crypto, 44 checks agree. Scenario fix: a limited cleanup leaves open which expired records go, so the scan after it compares only the count.

AC #4: the scenarios prove single use of take sequentially on each backend; concurrent take races across processes and languages need real backends and run in the interop matrix (TASK-103.8).

Revised after review: ownership checks (former STORE-097/098, not_owned) dropped at the user's request. Option (a) for tsl.state: sealed, keyring required; no tool creates keys on its own (STORE-095); profile create makes the key file at <config>/telematik/profiles/<name>/store.kek unless TI_STORE_KEK_PATH names one. New section L (STORE-120-132): shared profile/store commands, store doctor with --json, safe debug listing, trace, recovery (cache recreated, state never touched), hints table, HITL isolation via TI_STATE_DIR/TI_CACHE_DIR/TI_STORE_KEK_PATH. Corpus now 126 cases; Node cross-check still 44/44.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
spec/store: 97 rules (A-L) for the shared sealed store of the CLIs: operations, namespaces, hashed names and blind-index tags, HKDF derivation, AES-256-GCM sealed records, keyring with key-file wrapper, SQLite schema (checked with sqlite3 3.54), files backend, profiles, format levels and migrations, operation commands with hints. Corpus of 126 cases generated deterministically by tool/ (Go, stdlib only); go test checks the manifest is current, cited rules exist, the reference passes and the verifier rejects wrong answers; crypto vectors cross-checked with Node.js node:crypto (44/44). Left to later tasks: implementations (103.3, 103.6, 111), interop matrix and concurrent take races (103.8), platform wrappers (104).
<!-- SECTION:FINAL_SUMMARY:END -->
