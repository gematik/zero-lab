---
id: TASK-288
title: 'tipki: tag a release that carries fetch, titls and the TUC_PKI_006 responders'
status: To Do
assignee: []
created_date: '2026-11-11T19:44:00Z'
labels:
  - tipki
  - go
  - release
dependencies: []
references:
  - go/docs/development.md
priority: medium
ordinal: 304000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The latest tag go/tipki/v0.31.1 predates tipki/fetch, tipki/titls and the OCSP responder rule of TASK-270 (4f9cca4d). A consumer outside the workspace that takes the tagged version cannot import titls.OCSPTransport, and its OCSP check refuses SM(C)-B certificates whose responder the TSL lists but RFC 6960 does not authorize: with v0.31.2-0.20261106180818-4c2a720247df the test SM(C)-B of GEM.SMCB-CA9 TEST-ONLY failed with ocsp_responder_untrusted, with 21aea8333e24 it is good. zeta-pdp-go (go.mod) therefore pins the pseudo-version v0.31.2-0.20261110185948-21aea8333e24. Rule: go/docs/development.md, Part B.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A tag go/tipki/vX.Y.Z exists at or after 21aea833 and go list -m -versions shows it
- [ ] #2 The gated suites the tipki release needs have run and are recorded
<!-- AC:END -->
