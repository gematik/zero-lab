---
id: TASK-334
title: >-
  pkcs12, ti-pkcs12: the PrivateKeyInfo check agrees on OID and parameter edge
  cases
status: To Do
assignee: []
created_date: '2026-11-15T10:02:00Z'
labels:
  - pkcs12
  - rust
  - go
dependencies: []
ordinal: 349000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Found by the review of TASK-329 (2026-11-15), with a differential probe of go/pkcs12 CheckPrivateKeyInfo against rust/ti-pkcs12's check: OIDs longer than 39 bytes and OID 2.1967 (06028f7f) are accepted by Go and refused by Rust (const-oid limits); an OID arc of 2^32 is refused by Go and accepted by Rust; parameters in high-tag-number form (9f8100, bf810000) are refused by Go and accepted by Rust; parameters 2400, 2403040100 and 0b00 are accepted by Go and refused by Rust. None is reachable with random plaintext, and spec/pkcs12 P12-041 states no OID or parameter rules. The probe inputs are in the session scratchpad (pkidiff) and should become shared corpus cases or fuzz seeds.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 spec/pkcs12 states the OID and AlgorithmIdentifier parameter rules of P12-041
- [ ] #2 Go and Rust agree on every edge case above, pinned by shared corpus cases or differential tests
<!-- AC:END -->
