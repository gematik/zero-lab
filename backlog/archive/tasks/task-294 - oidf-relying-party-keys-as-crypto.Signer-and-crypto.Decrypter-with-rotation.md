---
id: TASK-294
title: 'oidf: relying party keys rotate with an overlap'
status: To Do
assignee: []
created_date: '2026-11-12T21:08:00Z'
updated_date: '2026-11-15T09:05:00Z'
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
- [ ] #1 The published JWKS can hold the next and the previous key, and decryption works with each until the exp of the last document that published it
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
2026-11-14: keys as crypto.Signer, an ECDH key agreement and a tls.Certificate come with TASK-315 (ECDH-ES needs a key agreement, not a crypto.Decrypter). What is left here: publishing the next and the previous key, so they rotate with an overlap (servers.md rule 22).

2026-11-15: aborted. Keys as functions came with TASK-315; the rotation that is left is TASK-327.
<!-- SECTION:NOTES:END -->
