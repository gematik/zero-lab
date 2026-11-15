---
id: TASK-327
title: 'oidf: relying party keys rotate with an overlap'
status: To Do
assignee: []
created_date: '2026-11-15T09:05:00Z'
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
