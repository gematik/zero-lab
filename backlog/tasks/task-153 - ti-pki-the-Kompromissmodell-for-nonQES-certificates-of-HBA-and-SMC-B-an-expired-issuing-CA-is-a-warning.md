---
id: TASK-153
title: >-
  ti-pki: the Kompromissmodell for nonQES certificates of HBA and SMC-B (an
  expired issuing CA is a warning)
status: To Do
assignee: []
created_date: '2026-10-28T18:44:00Z'
labels:
  - ti-pki
  - pki
  - spec
milestone: m-0
dependencies: []
priority: high
type: bug
ordinal: 161000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
ti-pki validates every chain by the PKIX shell model: each certificate valid at the reference time. gemKPT_PKI_TIP V2.14.0 2.4 assigns validity models by certificate type: 2.4.1 shell model for components (devices, services) and the eGK's nonQES certificates; 2.4.2 Kompromissmodell for all nonQES X.509 certificates of the HBA and the SMC-B: checked by the chain model (each CA valid when it issued the certificate below), validity periods set as in the shell model; 2.4.3 chain model for QES. gemSpec_PKI V2.28.0 Tab_PKI_271: the TSL status inaccord holds also for time-expired HBA/SMC-B CA certificates when nonQES signatures are checked by the Kompromissmodell; TUC_PKI_018 checks the end entity's validity (TUC_PKI_002) and the CA's TSL status (step 5), not the CA's notAfter. Example: an SMC-B certificate valid until 2028 under GEM.SMCB-CA9 TEST-ONLY, which expired 2025-08-28, is valid with a warning.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The validity model follows the end entity's type: Kompromissmodell for C.HCI.AUT, C.HCI.ENC, C.HCI.OSIG, C.HP.AUT, C.HP.ENC; shell model for every other type (components, eGK)
- [ ] #2 Under the Kompromissmodell each CA must have been valid when it issued the certificate below (its notBefore); valid then but expired now is a warning naming the CA, not valid then is an error as before; the end entity is always checked at the reference time (TUC_PKI_002)
- [ ] #3 Tests name the requirement: an SMC-B and an HBA certificate under an expired CA are valid with the warning, a component certificate under the same CA is invalid, a certificate issued after the CA expired is invalid
- [ ] #4 The new warning code is in ErrorCode::ALL, the pki verify schema, AGENTS.md and the Unreleased notes
<!-- AC:END -->
