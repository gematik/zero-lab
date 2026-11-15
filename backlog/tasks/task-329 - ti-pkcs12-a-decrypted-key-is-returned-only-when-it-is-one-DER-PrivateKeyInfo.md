---
id: TASK-329
title: 'ti-pkcs12: a decrypted key is returned only when it is one DER PrivateKeyInfo'
status: To Do
assignee: []
created_date: '2026-11-15T09:24:00Z'
labels:
  - rust
  - pkcs12
  - security
dependencies: []
ordinal: 344000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Found while fixing TASK-326 in go/pkcs12: rust/ti-pkcs12/src/lib.rs (~487 shrouded key bags, ~499 key bags) returns the decrypted octets without parsing them. On a file without MAC a wrong password yields random plaintext whose padding is valid about once in 256 tries, and that garbage comes back as a key. The Go fix (go/pkcs12 internal/syntax CheckPrivateKeyInfo, RFC 5958: one DER SEQUENCE, nothing after it, version 0 or 1, AlgorithmIdentifier, non-empty privateKey, attributes [0], publicKey [1] only in v1) is the model; P12-041 in spec/pkcs12 may need to say so (see the spec task).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A wrong password on a file without MAC never yields a key, shown by a test that forces valid padding (as Go's TestP12_034AWrongPasswordWithoutMACNeverYieldsAKey does)
- [ ] #2 Decrypted key bags are checked as one DER PrivateKeyInfo before they are returned, with a fuzz target
<!-- AC:END -->
