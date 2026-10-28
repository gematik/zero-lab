---
id: TASK-151
title: 'ti identity: an HBA''s AUT identity as well as an SMC-B''s'
status: In Progress
assignee: []
created_date: '2026-10-28T17:27:00Z'
updated_date: '2026-10-28T18:23:00Z'
labels:
  - ti-cli
  - identity
milestone: m-0
dependencies: []
priority: medium
type: enhancement
ordinal: 159000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
ti identity, idpd authenticate and directory login owner take any authentication certificate (digitalSignature without contentCommitment) with a brainpoolP256r1 or P-256 key, so an HBA's C.HP.AUT works as well as an SMC-B's C.HCI.AUT, from a PKCS#12 export or as a card at the Konnektor (CertRef C.AUT); a QES certificate is excluded by its contentCommitment. Help, AGENTS.md, README and the code's docs call it the SMC-B identity, and the card path names only PIN.SMC (an HBA's AUT key needs PIN.CH). Not yet run with a real HBA.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Help, AGENTS.md, README and docs say SMC-B or HBA (institution or practitioner) where the identity is meant; ePA-only uses (clientAttest) keep naming the SMC-B
- [x] #2 The card path names the PIN the card needs: PIN.SMC for an SMC-B, PIN.CH for an HBA
- [x] #3 A test proves an HBA AUT certificate (C.HP.AUT test fixture) is selected and a QES certificate is not
- [ ] #4 HITL: identity inspect and idpd authenticate with a real HBA at the Konnektor (the maintainer runs it)
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Done on feat/ti-cli-help-and-search: wording SMC-B or HBA in help, AGENTS.md, README, schema identity-inspect, docs; --card help and the guide name PIN.SMC / PIN.CH (a PIN-specific hint on the signing fault would need the Konnektor's fault code for an unverified PIN, not guessed); TEST-ONLY HBA fixtures from generate.sh (GEM.HBA-CA, C.HP.AUT, C.HP.QES with oid_arzt admission, Telematik-ID 1-HBA-TESTONLY01; the run regenerated all identity fixtures, keys are random); tests inspect_selects_the_aut_pair_of_an_hba, hba-qes.p12 identity_not_found, is_aut unit test. just check green. Left: AC4, HITL with a real HBA.
<!-- SECTION:NOTES:END -->
