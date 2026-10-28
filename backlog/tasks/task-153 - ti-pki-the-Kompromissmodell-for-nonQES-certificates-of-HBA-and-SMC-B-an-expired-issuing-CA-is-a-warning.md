---
id: TASK-153
title: >-
  ti-pki: the Kompromissmodell for nonQES certificates of HBA and SMC-B (an
  expired issuing CA is a warning)
status: In Progress
assignee: []
created_date: '2026-10-28T18:44:00Z'
updated_date: '2026-10-28T19:31:00Z'
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
- [x] #1 The validity model follows the end entity's type: Kompromissmodell for C.HCI.AUT, C.HCI.ENC, C.HCI.OSIG, C.HP.AUT, C.HP.ENC; shell model for every other type (components, eGK)
- [x] #2 Under the Kompromissmodell each CA must have been valid when it issued the certificate below (its notBefore); valid then but expired now is a warning naming the CA, not valid then is an error as before; the end entity is always checked at the reference time (TUC_PKI_002)
- [x] #3 Tests name the requirement: an SMC-B and an HBA certificate under an expired CA are valid with the warning, a component certificate under the same CA is invalid, a certificate issued after the CA expired is invalid
- [x] #4 The new warning code is in ErrorCode::ALL, the pki verify schema, AGENTS.md and the Unreleased notes
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
ti-pki: ValidityModel {Shell, Compromise} in path.rs, PathOptions::model; the Validator takes it from the end entity's type (given or detected): Compromise for C.HCI.AUT/ENC/OSIG and C.HP.AUT/ENC, Shell otherwise. Under Compromise each CA is checked at the notBefore of the certificate it issued; expired at the reference time but valid then is the warning issued_before_ca_expiry (ErrorCode 24). Test PKI (just test-pki, regenerated): sub-ca-short (2026 only) with ee-short-hci-aut, -hp-aut, -fd-tls-s and ee-after-short, validated at 2028-01-01. Tests: kompromissmodell_accepts_a_ca_that_expired_after_issuing, kompromissmodell_rejects_a_certificate_issued_after_the_ca_expired, shell_model_rejects_a_chain_whose_ca_has_expired, the_certificate_type_picks_the_validity_model, the_validity_model_follows_the_certificate_type. pki-verify schema, AGENTS.md, ti-pki and ti-cli Unreleased notes. just check green. Waiting for the maintainer's run with the GEM.SMCB-CA9 TEST-ONLY certificate.

2026-10-28, maintainer: pki inspect still showed the expired CA as a red error. The trust tree (chain_tree, used by pki inspect and pki verify) now applies the model of the first certificate's type: under the Kompromissmodell a CA expired after it issued shows in yellow as 'expired …, valid when it issued'. Test: the_trust_tree_shows_the_validity_model_of_the_certificate_type.
<!-- SECTION:NOTES:END -->
