---
id: TASK-329
title: 'ti-pkcs12: a decrypted key is returned only when it is one DER PrivateKeyInfo'
status: Done
assignee: []
created_date: '2026-11-15T09:24:00Z'
updated_date: '2026-11-15T11:13:00Z'
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
- [x] #1 A wrong password on a file without MAC never yields a key, shown by a test that forces valid padding (as Go's TestP12_034AWrongPasswordWithoutMACNeverYieldsAKey does)
- [x] #2 Decrypted key bags are checked as one DER PrivateKeyInfo before they are returned, with a fuzz target
<!-- AC:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
ti-pkcs12 holds decrypted and plain key bags to the same strict PrivateKeyInfo check; a plain key bag is normalised from BER in every layer first (new ber.rs, a port of Go's, with a ber_to_der fuzz target); intermediate key buffers are zeroized. Edge-case parity with Go is TASK-334, shared BER gaps TASK-335. Merged at d8f24089.
<!-- SECTION:FINAL_SUMMARY:END -->
