---
id: TASK-275
title: 'jwz: a key without alg is bound to one algorithm (RFC 8725 §3.1)'
status: To Do
assignee: []
created_date: '2026-11-08T15:20:00Z'
updated_date: '2026-11-08T15:26:00Z'
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

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Design question before building (maintainer, 2026-11-08; not in jwz 0.2.0): a blanket refusal of JWKs without alg would break common issuers (alg is optional, RFC 7517). jwz already rules out cross-type confusion (key type and curve must fit). Decide which remaining ambiguities are dangerous (HMAC hash sizes, oct for dir vs key wrap) and which are names of one primitive (EdDSA/Ed25519; ES256 on brainpoolP256r1 vs BP256R1 under ti_legacy, which a gematik IDP key without alg would hit). Check real JWKs (IDP-Dienst, TASK-251's issuers) first.
<!-- SECTION:NOTES:END -->
