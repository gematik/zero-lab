---
id: TASK-438
title: >-
  gematik: PKI test suite with .sig/.ocsp on its TSL provider, the SUT simulator
  in the release and published images
status: To Do
assignee: []
created_date: '2026-11-24 10:18'
updated_date: '2026-11-24 12:55'
labels:
  - ti-pki
  - tests
dependencies:
  - TASK-436
references:
  - 'https://github.com/gematik/app-PkiTestsuite'
priority: low
type: external
ordinal: 436000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Found in the PKI test suite spike (TASK-436, doc-8). app-PkiTestsuite 8.1.0 serves XMLDSig TSLs only, without the detached signature (.sig) and signer OCSP response (.ocsp) that gemSpec_TSL 6.3.1.3 has the TSL service publish and that ti-pki verifies by (TASK-166, spec/tsl-detached, RFC doc-3). Its release zip lacks pkits-sut-server-sim-exec.jar, and gematik publishes no images of the suite. Ask gematik (issue on github.com/gematik/app-PkiTestsuite or the PKI team) for the three, referring to doc-3. Until .sig/.ocsp exist, the TslApproval cases cannot test ti-pki's TSL path.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 gematik's answer on .sig/.ocsp in the TSL provider is recorded
- [ ] #2 gematik's answer on the SUT simulator in the release and on published images is recorded
- [x] #3 gematik's PKI test suite issues its test end-entity certificates with an AIA OCSP URI (the responder's /ocsp/{seqNr}), recorded with the suite version that carries it
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
2026-11-24: the maintainer reports that gematik makes the AIA change in the suite: its test certificates get an AIA OCSP URI. ti-pki takes the OCSP address from the AIA (rust/ti-pki/src/ocsp.rs:1075), so with it the suite's OCSP cases reach the core without TASK-437.

2026-11-24, release 8.1.1 (zip sha256 7b5186c0d208d29d3dee7007f42029e8e55fd85045891076ba155e948832ee71): new test object type IntermediaerServerInternet (WIP) with test data under testDataTemplates/certificates/ecc-internet/ (smcbClient, tsl-signer) and a SUT simulator pkits-sut-server-sim-internet (TSL from the provider only, no backup URL; OCSP at a configured service-url). Its SMC-B certificates (GEM.SMCB-CA58 TEST-ONLY, valid 2026-10-20 to 2031-10-19, EKU clientAuth) carry AIA OCSP http://127.0.0.1:8083/ocsp/, the suite's responder. Open points: the responder serves only POST /ocsp/{seqNr}, so the AIA path without a sequence number does not match it yet; the address is fixed to 127.0.0.1, so a host must share the responder's network namespace. Correction: the certificates of the ecc tree already carried an AIA in 8.1.0, but to http://ehca.gematik.de/ecc-ocsp, not to the suite's responder. TSLs are still XMLDSig signed (TslSignerNonQes), no .sig/.ocsp; the internet SUT simulator is in the source, not checked whether in the zip.
<!-- SECTION:NOTES:END -->
