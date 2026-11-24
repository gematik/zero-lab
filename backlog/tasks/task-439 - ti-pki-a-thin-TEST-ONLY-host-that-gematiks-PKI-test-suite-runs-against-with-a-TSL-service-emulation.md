---
id: TASK-439
title: >-
  ti-pki: a thin TEST-ONLY host that gematik's PKI test suite runs against, with
  a TSL service emulation
status: To Do
assignee: []
created_date: '2026-11-24 10:31'
updated_date: '2026-11-24 13:06'
labels:
  - ti-pki
  - tests
dependencies:
  - TASK-437
  - TASK-438
references:
  - backlog/docs/doc-8
  - docs/design/testing.md
  - spec/tsl-detached/README.md
priority: medium
type: feature
ordinal: 437000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
From the spike TASK-436 (doc-8): gematik's PKI test suite (app-PkiTestsuite 8.1.0) tests a host: a server that loads the TSL from the suite's TSL provider, asks OCSP at the TSL's ServiceSupplyPoint (/ocsp/{seqNr}) and accepts or refuses the suite's client certificate in a TLS 1.2 handshake. Conformance is tested on the core, so the host is very thin and stable: blocking std, rustls server, every trust decision (TSL, chain, OCSP, CertificateVerify signature incl. brainpool) by ti-pki. The suite serves XMLDSig TSLs only; the core authenticates by .sig/.ocsp (TASK-166). A separate TEST-ONLY container emulates gematik's TSL service: it passes tsl.xml/tsl.sha2 through unchanged and publishes next to them the .sig over the exact bytes (signed with the suite's TEST-ONLY key of the signer named in the XMLDSig) and the signer's .ocsp from the suite's responder; the host signs nothing. Everything runs in Docker next to rust/ti-pki/conformance/pkits/, as a gated suite with one just recipe (docs/design/testing.md).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The host and the TSL service emulation run with docker compose next to the suite, no Java or Maven on the host machine
- [ ] #2 InitialStateTest#checkInitialState passes against the host
- [ ] #3 Each approval test's result against the host is recorded in doc-8, every failure with its reason (core finding, decision, or host limitation)
- [ ] #4 The host holds no trust logic: TSL, chain, OCSP and CertificateVerify are decided by ti-pki
- [ ] #5 A gated recipe runs the suite and is listed in the development guide's gated-test table
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Order: TASK-437 (core picks the OCSP address from the TSL's ServiceSupplyPoint: the suite's ecc certificates carry an AIA to ehca.gematik.de, not to its responder, so otherwise the host would hold TUC_PKI_006 logic) -> ti-tls ClientCertVerifier (own task) -> this task.

1. ti-tls: a rustls ClientCertVerifier over the core, the counterpart of TiVerifier (ti-tls/src/verifier.rs): Validator::validate with the HCI_AUT profile (profile.rs), OcspChecker; TLS 1.2 CertificateVerify through verify_tls12_signature with TI_SCHEMES (brainpool included). Reusable, so the host keeps no trust code.
2. Host: an unpublished workspace crate, TEST-ONLY, blocking std, workspace deps only (ti-pki, ti-tls, ti-client's Http transport, rustls). It does I/O only: env config, a thread that ticks the Reloader (ReloadPolicy interval = the suite's tslDownloadIntervalSeconds), a Transport wrapper that appends ?activeTslSeqNr=<the loaded TSL's number> (the suite's download protocol), a std TcpListener with rustls ServerConnection, one thread per connection. Server key and certificate are made at image build (P-256, TEST-ONLY; the suite only checks expiry), never committed.
3. TSL service emulation: a TEST-ONLY container, alpine pinned by digest with python3 (stdlib) and openssl. It proxies the suite's tsl-provider and passes tsl.xml/tsl.sha2 through unchanged. Next to them it publishes .sig = SEQUENCE{ecdsa-with-SHA256, BIT STRING ECDSA-Sig-Value, signer certificate} over the exact bytes, signed with the suite's TEST-ONLY TSL-Signing-Unit p12 whose certificate the XMLDSig names, and .ocsp = openssl ocsp for the signer at the ServiceSupplyPoint of its CA in that TSL. Test material comes from the pkits image, never from the repository.
4. compose: suite (testObjectType IntermediaerServer: SMC-B client certificates, brainpool, HCI_AUT profile exists in the core), simulators, emulation, host. One just recipe, an entry in the gated-test table.
5. Run allTests.txt; record per test in doc-8: pass, or failure with its reason (core finding -> task, decision, host limitation).

Open: TrustConfig::validate requires tsl_url to be https (the .sha2 is read from it). The emulation serves HTTPS with a TEST-ONLY CA made at image build and the host trusts that CA through its transport config. No check is relaxed for it.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
OCSP address: the host relies on the AIA of the suite's certificates, which gematik adds to the suite (TASK-438). TASK-437 (address from the TSL's ServiceSupplyPoint, TUC_PKI_005) stays a separate spec finding and no longer blocks this task.

Suite 8.1.1: target test object type IntermediaerServerInternet; its ecc-internet certificates carry AIA http://127.0.0.1:8083/ocsp/ (TASK-438 notes). The host runs in the ocsp-responder's network namespace (compose network_mode) until gematik makes the address configurable; the responder's path still needs the sequence number.

gemLibPki check (TASK-437 notes): gematik's SUT simulators, the internet variant included, take the OCSP address from the TSL SSP, not the AIA. TASK-437 blocks this task again.
<!-- SECTION:NOTES:END -->
