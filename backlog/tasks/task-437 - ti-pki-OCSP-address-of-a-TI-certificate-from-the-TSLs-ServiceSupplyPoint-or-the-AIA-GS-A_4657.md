---
id: TASK-437
title: >-
  ti-pki: OCSP address of a TI certificate from the TSL's ServiceSupplyPoint or
  the AIA (GS-A_4657)
status: To Do
assignee: []
created_date: '2026-11-24 10:18'
updated_date: '2026-11-24 10:43'
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

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Spec checked (gemSpec_PKI 2.28.0): TUC_PKI_006 (GS-A_4657-03, step 'Ermittlung der OCSP-Adresse') delegates to TUC_PKI_005 (GS-A_4656, https://gemspec.gematik.de/docs/gemSpec/gemSpec_PKI/gemSpec_PKI_V2.28.0/#GS-A_4656): find the issuing CA in the TSL (TUC_PKI_003) and take the URI of its ServiceSupplyPoint; no ServiceSupplyPoint is the error SERVICESUPPLYPOINT_MISSING. The certificate's AIA is not a source in the TI profile. The address may also be kept in the system's trust store (note of TUC_PKI_005). Nothing in spec/pki-validation or spec/pki-profiles records TUC_PKI_005 today, so ti-pki's AIA lookup is an unrecorded deviation. The data is already there: TrustStore::listed_responders holds (CA certificate, ServiceSupplyPoint URL) from the TSL (truststore.rs:50), and RevocationChecker::check receives the store (ocsp.rs:1069). The web profile keeps the AIA (TLSV-044). The suite's test certificates have no AIA at all.
<!-- SECTION:NOTES:END -->
