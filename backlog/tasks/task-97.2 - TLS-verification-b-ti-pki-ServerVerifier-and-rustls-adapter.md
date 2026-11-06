---
id: TASK-97.2
title: 'TLS verification (b): ti-pki ServerVerifier and rustls adapter'
status: To Do
assignee: []
created_date: '2026-11-06T07:36:00Z'
labels:
  - ti-pki
  - security
dependencies: []
parent_task_id: TASK-97
priority: medium
ordinal: 236000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-97 part (b): the verifier in ti-pki, held to spec/pki-validation.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 ti_pki::tls verifies chain, server name and stapled OCSP under the ti and web profiles over an atomically swapped trust snapshot and a bounded verdict cache; the corpus passes
- [ ] #2 feature rustls supplies a ServerCertVerifier; every new parser (CRL) has a fuzz target
<!-- AC:END -->
