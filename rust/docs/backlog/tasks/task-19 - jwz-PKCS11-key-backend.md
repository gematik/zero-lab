---
id: TASK-19
title: 'jwz: PKCS#11 key backend'
status: To Do
assignee: []
created_date: '2026-10-10 05:58'
labels:
  - jwz
  - hsm
dependencies: []
priority: low
ordinal: 19000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Keys in HSMs and smartcards through PKCS#11 (cryptoki), as a crate of its own implementing jwz's key traits (Signer, AsyncSigner, KeyAgreement); jwz's tree stays free of cryptoki.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 ES256 signing and ECDH-ES key agreement with a SoftHSM token in tests
- [ ] #2 just jwz-backends still passes for jwz, jwz-brainpool and ti-jwz
<!-- AC:END -->
