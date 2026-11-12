---
id: TASK-294
title: 'oidf: relying party keys as crypto.Signer and crypto.Decrypter, with rotation'
status: To Do
assignee: []
created_date: '2026-11-12T21:08:00Z'
labels: []
dependencies: []
ordinal: 310000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The relying party loads its signing and encryption keys as raw private keys from files or inline JWK (relying_party.go), against docs/design/keys.md rule 1, and publishes one key. A key in an HSM cannot be used, and a key cannot be rotated with an overlap. Found by zeta-pdp-go, which needs it for the login of insured persons at a sektoral IDP (its TASK-54) or as named.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Keys are handed in as crypto.Signer and crypto.Decrypter; the published JWKS can hold the next and the previous key
<!-- AC:END -->
