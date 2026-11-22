---
id: TASK-327
title: 'oidf: relying party keys rotate with an overlap'
status: To Do
assignee: []
created_date: '2026-11-15T09:05:00Z'
updated_date: '2026-11-22 11:54'
labels:
  - oidf
  - go
  - keys
dependencies: []
ordinal: 342000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Since TASK-315 the relying party takes its keys as functions (oidf.Keys: crypto.Signer, an ECDH key agreement, a tls.Certificate) and publishes exactly one of each. What is missing is rotation with an overlap (servers.md rule 22): the next federation signing key published at least 24 hours before use (gemSpec_IDP_FedMaster A_28859), the previous encryption key kept for decryption until the exp of the last document that published it (gemSpec_IDP_FD A_28209), and every key replaced within 398 days (A_23185-01). statement_check.go refuses a top-level jwks with any key but the signing key; that rule has to allow the announced next key. Replaces the rotation part of TASK-294.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The entity statement can publish the next signing key ahead of its use, and the relying party switches to it without a restart
- [ ] #2 An ID token encrypted to the previous encryption key decrypts until the exp of the last document that published that key
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
2026-11-22, maintainer: key change looks like a configuration matter. Checked against the code: a new key is configuration and takes effect with a rollout (servers.md rule 8), but oidf.Keys holds exactly one key of each kind and statement_check.go refuses a jwks with any key but the signing key. So a rollout swaps keys without overlap: (1) a new signing key appears in the entity statement only when it is already in use, where A_28859 asks for it 24 hours ahead; (2) an IDP keeps encrypting ID tokens to the old key as long as it holds the old statement (up to its exp), and those logins fail after the swap. The code left is small: Keys takes an optional next signing key (published, not used) and an optional previous decryption key (used for a kid that is not the current one); the host reads both from configuration like the current ones. Awaiting the maintainer's decision whether that is worth it or the overlap is left to operations (swap only after the old statement expired).
<!-- SECTION:NOTES:END -->
