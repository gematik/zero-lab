---
id: TASK-437
title: >-
  ti-pki: OCSP address of a TI certificate from the TSL's ServiceSupplyPoint or
  the AIA (GS-A_4657)
status: To Do
assignee: []
created_date: '2026-11-24 10:18'
labels:
  - ti-pki
  - spec
dependencies: []
references:
  - backlog/docs
  - spec/pki-validation/README.md
  - rust/ti-pki/src/ocsp.rs
priority: medium
type: task
ordinal: 435000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Found in the PKI test suite spike (TASK-436, doc-8). ti-pki asks OCSP at the configured override, otherwise at the first AIA URL of the certificate (rust/ti-pki/src/ocsp.rs:1078; go/tipki/ocsp.go:839 the same); the ServiceSupplyPoints of the issuing CA's TSL entry only authorize the responder (TrustStore::listed_responders). gematik's PKI test suite writes its responder as ServiceSupplyPoint into each TSL and counts only requests sent there (OcspApprovalTests, verifyForCaCertificateWithoutServiceSupplyPoint). Check what TUC_PKI_006/GS-A_4657 and TUC_PKI_018 require as the source of the OCSP address in the TI profile, and either change the order or record the deviation in spec/pki-validation.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The requirement text on the source of the OCSP address is cited in spec/pki-validation
- [ ] #2 ti-pki and go/tipki follow it, or the deviation is recorded with the reason
<!-- AC:END -->
