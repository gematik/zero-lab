---
id: TASK-275
title: 'jwz: a key without alg is bound to one algorithm (RFC 8725 §3.1)'
status: To Do
assignee: []
created_date: '2026-11-08T15:20:00Z'
labels:
  - jwz
  - security
dependencies: []
priority: medium
ordinal: 291000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Found by TASK-258. RFC 8725 §3.1 (and RFC 9864 §7: one key, one algorithm): a JWK without alg verifies HS256, HS384 and HS512 alike; a SymmetricKey without alg serves both dir and AES key wrap; a KeyAgreement key serves every ECDH-ES variant. A key that names its algorithm is bound already (RFC 7517 §4.4).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 a JWE key (SymmetricKey, KeyAgreement) is made for one algorithm and refuses another
- [ ] #2 verify_with refuses a JWK without alg when the profile lists more than one algorithm its key type could serve, or the binding is stated otherwise, decided and recorded in ADR 0001
- [ ] #3 tests named after RFC 8725 §3.1 prove each case
<!-- AC:END -->
