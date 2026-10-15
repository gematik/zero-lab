---
id: TASK-103.1
title: 'spec/store: contract, corpus and generator for the shared sealed store'
status: To Do
assignee: []
created_date: '2026-10-15 17:45'
updated_date: '2026-10-15 17:51'
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
- [ ] #1 spec/store/README.md has rules STORE-nnn, result codes and security considerations; spec/README.md lists it
- [ ] #2 spec/store/tool (Go, stdlib only) regenerates testdata byte for byte and verifies every vector and negative case
- [ ] #3 vectors cross-checked once against an independent implementation, recorded in CONFORMANCE.md
- [ ] #4 operation scenarios cover TTL, take races, partial batch failure and cursor paging
- [ ] #5 implementable on the JVM with JCA only (AES-GCM, HMAC, HKDF over HMAC); the adapter contract is language-neutral so a Kotlin/Java adapter can run the corpus
- [ ] #6 a rule forbids private key bytes in the store (docs/design/keys.md rule 1): only handles and references
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
JVM (zeta-cli, ZETA SDK) is a third consumer; its implementation is deferred (separate task) but the spec must not need anything beyond JCA. SQLite on the JVM means sqlite-jdbc (JNI), acceptable for CLIs only (docs/interop.md).
<!-- SECTION:NOTES:END -->
