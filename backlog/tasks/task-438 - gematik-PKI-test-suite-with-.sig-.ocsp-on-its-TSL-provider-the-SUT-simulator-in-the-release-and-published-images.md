---
id: TASK-438
title: >-
  gematik: PKI test suite with .sig/.ocsp on its TSL provider, the SUT simulator
  in the release and published images
status: To Do
assignee: []
created_date: '2026-11-24 10:18'
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
<!-- AC:END -->
