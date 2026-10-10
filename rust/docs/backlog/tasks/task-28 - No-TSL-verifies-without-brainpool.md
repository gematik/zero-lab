---
id: TASK-28
title: No TSL verifies without brainpool
status: To Do
assignee: []
created_date: '2026-10-10 17:08'
labels:
  - ti-pki
dependencies: []
priority: low
ordinal: 24000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Both TSL signer CAs (GEM.TSL-CA3, GEM.TSL-CA28 TEST-ONLY) are brainpool, so under algorithms::NIST (ti --nist-only) every TSL fails with xml_signature_error (TSLSIG-012) and a NIST-only client gets no intermediates from the TSL, only --issuer / --intermediates. Nothing to fix in ti while gematik signs the TSL with brainpool; revisit when a NIST TSL signer CA appears.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 a NIST-only client gets TSL CAs once gematik publishes a TSL with a NIST signer CA, or the task is closed as out of our hands
<!-- AC:END -->
