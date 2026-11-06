---
id: TASK-97.2
title: >-
  TLS verification (b): ti profile in ti-pki, web profile and rustls verifiers
  in ti-tls
status: In Progress
assignee: []
created_date: '2026-11-06T07:36:00Z'
updated_date: '2026-11-06T07:57:00Z'
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

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Maintainer, 2026-11-06: ti-pki has nothing to do with hardening the Web-PKI. ti-pki implements the ti profile only; a new adapter-level crate ti-tls holds the web profile (system roots via rustls-native-certs, rustls-webpki paths, the hardening rules), the rustls verifiers for both profiles and the ClientConfig per profile. Dependencies approved for ti-tls: rustls, rustls-webpki, rustls-native-certs (all already in the tree).
<!-- SECTION:NOTES:END -->
