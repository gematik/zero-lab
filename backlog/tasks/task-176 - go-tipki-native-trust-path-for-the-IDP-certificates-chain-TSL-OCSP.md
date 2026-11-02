---
id: TASK-176
title: 'go/tipki: native trust path for the IDP certificates (chain, TSL, OCSP)'
status: In Progress
assignee: []
created_date: '2026-11-02T06:16:00Z'
updated_date: '2026-11-02T13:52:00Z'
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
- [x] #2 stage 2: roots.json walk
- [x] #3 stage 3: detached TSL
- [x] #4 stage 4: OCSP
- [ ] #5 stage 5: gemidp verifies both IDP certificates, TASK-171
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
2026-11-02: stage 1 on feat/go-tipki. Maintainer: chain building without a network, from the same format ti produces. So go/tipki reads ti-pki's Bundle (ParseBundle); ti pki trust export is on the parked branch feat/ti-trust-export and has to return for a bundle to exist. Corpus: every non-RSA fixture at three times, under both models and tampered, and bundle values, all matching ti-pki. A real SMC-B chain to GEM.RCA5 TEST-ONLY checks out.

2026-11-02, maintainer: OCSP is not air-gapped. The bundle makes chain building independent of the network; revocation is asked online. A signer status in a bundle counts for 2 h (TSLDET-021), after that the signer's responder is asked, and no route to a responder means no verification.

2026-11-02, maintainer: option 1 of the whole spectrum. Go reads and checks every type, role and profile; the trust path stays ECDSA only, so RSA is refused.

2026-11-02: stage 2. ParseRoots and WalkRoots port the A_28419 walk, TrustedRoots takes a bundle. Maintainer: RSA admitted in the walk alone, since the TI's roots alternate between ECC and RSA; chains stay ECDSA only. The real prod and nonprod files reach the same 10 roots as ti-pki; without RSA they stop at 2.

2026-11-02: stage 3. ParseDetachedSignature, VerifyTSL and the signer checks, parseTSL with encoding/xml, MatchToRoots, LoadTrustStore. Not ported, as not needed for a chain: the sequence-number and update rules (TSLSIG-053), the anchor announcement warning (TSLSIG-060), scheme information. The signer's status needs OCSP and comes with stage 4, whose manifest entries are skipped until then, so AC 3 stays open.

2026-11-02, maintainer: RSA in Go, same as Rust, which replaces the ECDSA-only rule of option 1. Go's verification now has ti-pki's algorithm set: RSA PKCS#1 v1.5 and PSS with SHA-256, SHA-384 and SHA-512, and ECDSA with the fixed pairs of curve and hash.

2026-11-02, maintainer: go/brainpool unfrozen, as tipki's trust path uses it; it now also decodes compressed points, so a compressed signer key is refused at TSLSIG-035 as in ti-pki. Added TSLSIG-053 (CheckSequence, LoadTrustStore takes the stored state), TSLSIG-060 (the announcement warning), the production marking and scheme information. Left: a compressed P-256 key still fails in crypto/x509 at parsing.

2026-11-02, maintainer: compressed points removed from go/brainpool again, which accepts uncompressed points only. A compressed signer key is refused at parsing there, and at TSLSIG-035 in ti-pki.

2026-11-02: stage 4. OCSPRequest, VerifyResponse with responder authorization and certHash, OCSPChecker with retries, rest and an in-memory cache, ApplyRevocation, the signer's status. All manifest entries of spec/tsl-detached now run. Not ported: the persistent CacheStore. Standing differences, pinned in TestOCSP002: Rust accepts three flips outside what a signature covers, which Go refuses; 99 flips inside the embedded certificate are refused by another code. A real SMC-B chain got good OCSP from the real responders. The pieces are not yet one verdict: Rust's Validator (check_key, check_tsl_type, CAs revoked in the TSL, role order) is still to be ported.
<!-- SECTION:NOTES:END -->
