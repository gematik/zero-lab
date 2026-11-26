---
id: TASK-437
title: >-
  ti-pki: OCSP address of a TI certificate from the TSL's ServiceSupplyPoint or
  the AIA (GS-A_4657)
status: To Do
assignee: []
created_date: '2026-11-24 10:18'
updated_date: '2026-11-26 12:18'
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

2026-11-24, gemLibPki 6.1.0 (Maven Central sources; the library behind gematik's PKI test suite and its SUT simulators) has three OCSP address sources, each an OcspTransceiverFactory: (1) ti10.ocsp.TslBasedSspOcspTransceiverFactory, the default of TucPki018Verifier: first ServiceSupplyPoint of the issuing CA's TSP service, TE_1026_SERVICESUPPLYPOINT_MISSING if absent (TUC_PKI_005); (2) ti20.ocsp.CertificateBasedSspOcspTransceiverFactory: the certificate's AIA OCSP URL, TE_1026 if absent; the issuer still comes from the TSL; (3) ti10.ocsp.TucPki030OcspTransceiverFactory (QES, TUC_PKI_030): AIA, replaced by a matching OCSP URL from the BNetzA-VL's AdditionalServiceInformation. The pkits SUT simulators (pkits-sut-server-core, both variants, internal repo at 8.1.2-SNAPSHOT) set no factory, so they ask at the TSL SSP, also the internet variant whose test certificates carry AIA 127.0.0.1:8083/ocsp/. Consequence: a zero-lab SUT that behaves like gematik's reference asks at the SSP; the source is a per-profile choice (TI 1.0: SSP; TI 2.0: AIA), as in gemLibPki.

2026-11-26, maintainer's decision: ti-pki and go/tipki keep the AIA as the OCSP address source. Not pursued; archived.
<!-- SECTION:NOTES:END -->
