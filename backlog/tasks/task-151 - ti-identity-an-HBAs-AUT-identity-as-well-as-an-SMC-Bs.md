---
id: TASK-151
title: 'ti identity: an HBA''s AUT identity as well as an SMC-B''s'
status: To Do
assignee: []
created_date: '2026-10-28T17:27:00Z'
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
- [ ] #1 Help, AGENTS.md, README and docs say SMC-B or HBA (institution or practitioner) where the identity is meant; ePA-only uses (clientAttest) keep naming the SMC-B
- [ ] #2 The card path names the PIN the card needs: PIN.SMC for an SMC-B, PIN.CH for an HBA
- [ ] #3 A test proves an HBA AUT certificate (C.HP.AUT test fixture) is selected and a QES certificate is not
- [ ] #4 HITL: identity inspect and idpd authenticate with a real HBA at the Konnektor (the maintainer runs it)
<!-- AC:END -->
