---
id: TASK-15
title: 'jwz-brainpool: decrypt JWE with an epk on BP-256'
status: To Do
assignee: []
created_date: '2026-10-09 17:27'
labels:
  - jwz
  - brainpool
dependencies: []
priority: low
ordinal: 15000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Brainpool JWE is encryption only in jwz milestone 1 (ECDH-ES to BP-256 keys, as go/gemidp encrypts to the IDP with josebp). Decryption with a BP-256 key (the IDP side) is deferred.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 ti_legacy() accepts an epk on BP-256 (Policy::key_agreement_curves)
- [ ] #2 Decryption tests, including the jwcrypto-encrypted direction in jwz-brainpool's interop fixtures
- [ ] #3 Docs (jwz-brainpool and ti-jwz READMEs, ADR) no longer say encryption only
<!-- AC:END -->
