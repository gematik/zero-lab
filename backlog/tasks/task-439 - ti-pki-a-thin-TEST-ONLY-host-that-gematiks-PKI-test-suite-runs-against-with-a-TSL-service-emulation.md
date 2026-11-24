---
id: TASK-439
title: >-
  ti-pki: a thin TEST-ONLY host that gematik's PKI test suite runs against, with
  a TSL service emulation
status: To Do
assignee: []
created_date: '2026-11-24 10:31'
labels:
  - ti-pki
  - tests
dependencies:
  - TASK-436
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
