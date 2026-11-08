---
id: TASK-270
title: >-
  ti-pki: CA standing from the TSL and OCSP responders per TUC_PKI_006, as the
  spec says
status: To Do
assignee: []
created_date: '2026-11-08T09:52:00Z'
labels:
  - rust
  - ti-pki
  - security
dependencies: []
ordinal: 286000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
A ref SMC-B (GEM.SMCB-CA9 TEST-ONLY, expired 2025-08-28) failed ti pki verify with ocsp_responder_untrusted: ti checked the sub-CA by OCSP at its root, and the CA names the production root responder, certified by the production GEM.RCA11. gemSpec_PKI TUC_PKI_018 takes a CA's standing from its TSL ServiceStatus (step 5, Tab_PKI_271; the status also covers expired HBA/SMC-B CAs under the Kompromissmodell) and queries OCSP for the checked certificate only (step 7). TUC_PKI_006 step 5 authorizes a responder by its certificate among the TSL's OCSP services; RFC 6960 option 2 is a duty of the TSPs for new responder certificates (A_23142-01), not of the relying party. Maintainer's decision: follow the spec, remove the sub-CA OCSP check, and make a responder outside RFC 6960 a warning when the TSL lists it.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 the Validator checks revocation for the end entity only; skip_sub_ca_revocation is gone
- [ ] #2 a responder that is the issuing CA or its delegate (RFC 6960) is accepted silently; one the verified TSL lists as an OCSP service is accepted with the warning ocsp_responder_not_rfc6960; any other is ocsp_responder_untrusted
- [ ] #3 design docs, the GemLibPki comparison and the release notes say so; the stale row on expired CAs is corrected
- [ ] #4 the ref SMC-B under GEM.SMCB-CA9 TEST-ONLY verifies
<!-- AC:END -->
