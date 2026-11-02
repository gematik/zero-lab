---
id: TASK-176
title: 'go/tipki: native trust path for the IDP certificates (chain, TSL, OCSP)'
status: In Progress
assignee: []
created_date: '2026-11-02T06:16:00Z'
updated_date: '2026-11-02T06:37:00Z'
labels:
  - go
  - pki
  - security
dependencies: []
priority: high
ordinal: 186000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Maintainer, 2026-11-02, option A for TASK-171: the smallest native trust path, no helper. Stages, each closed by the maintainer: 1) chain building and path validation under spec/pki-path, 2) roots.json walk from the anchor, 3) TSL from the detached signature with one XML reader, its signer and the signer's status, 4) OCSP for the end entity with responder authorisation, 5) gemidp uses it, TASK-171. ECDSA on P-256, P-384 and brainpool only: narrower than ti-pki, and it fails closed. Each stage has a corpus ti-pki writes and go/tipki runs.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 stage 1: chain and path validation match ti-pki over the corpus
- [ ] #2 stage 2: roots.json walk
- [ ] #3 stage 3: detached TSL
- [ ] #4 stage 4: OCSP
- [ ] #5 stage 5: gemidp verifies both IDP certificates, TASK-171
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
2026-11-02: stage 1 on feat/go-tipki. Maintainer: chain building without a network, from the same format ti produces. So go/tipki reads ti-pki's Bundle (ParseBundle); ti pki trust export is on the parked branch feat/ti-trust-export and has to return for a bundle to exist. Corpus: every non-RSA fixture at three times, under both models and tampered, and bundle values, all matching ti-pki. A real SMC-B chain to GEM.RCA5 TEST-ONLY checks out.

2026-11-02, maintainer: OCSP is not air-gapped. The bundle makes chain building independent of the network; revocation is asked online. A signer status in a bundle counts for 2 h (TSLDET-021), after that the signer's responder is asked, and no route to a responder means no verification.

2026-11-02, maintainer: option 1 of the whole spectrum. Go reads and checks every type, role and profile; the trust path stays ECDSA only, so RSA is refused.
<!-- SECTION:NOTES:END -->
