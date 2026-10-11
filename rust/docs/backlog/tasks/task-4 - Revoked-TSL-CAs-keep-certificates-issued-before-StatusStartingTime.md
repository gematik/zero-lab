---
id: TASK-4
title: 'Revoked TSL CAs: keep certificates issued before StatusStartingTime'
status: Done
assignee: []
created_date: '2026-10-09 13:55'
updated_date: '2026-10-11 12:30'
labels:
  - ti-pki
  - tsl
  - spec
dependencies: []
references:
  - ti-pki/src/tsl.rs
priority: high
ordinal: 3000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
ZETA Guard keeps a certificate valid if its CA is revoked in the TSL but the certificate was issued before the CA's StatusStartingTime. ti-pki keeps only CAs in accord/granted and drops revoked CAs entirely. That was argued with an unauthenticated TSL; the TSL is now verified (spec/tsl-xmldsig), so decide whether to adopt the rule. Source: Obsidian note C_12791.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 decision recorded; if adopted, a certificate issued before StatusStartingTime under a revoked CA validates and one issued after does not
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Decided 2026-10-11: adopted. gemSpec_PKI V2.28.0 makes it normative: Tab_PKI_271 (ServiceStatus revoked: 'Bis zum Widerrufsdatum (im Element StatusStartingTime) ausgegebene End-Entity-Zertifikate müssen aber normal (also als gültig, falls nicht widerrufen) behandelt werden') and TUC_PKI_002 step 5 (notBefore of the end entity against StatusStartingTime). The earlier objection (unauthenticated TSL) no longer holds since the TSL is verified. ti-pki keeps revoked CAs with a StatusStartingTime as candidates (tsl::Intermediate::revoked_since, TrustStore::revoked_since); the validator warns issued_before_ca_revocation or fails ca_revoked_in_tsl for the issuing CA; a revoked CA without the time stays out. ti-cli: tsl show reports revoked_since, tsl bundle leaves revoked CAs out (curl/Java cannot apply the rule). Live: the RU TSL lists 14 revoked SMC-B CAs (2026-09-28), PU none.
<!-- SECTION:NOTES:END -->
