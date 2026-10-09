---
id: TASK-4
title: 'Revoked TSL CAs: keep certificates issued before StatusStartingTime'
status: To Do
assignee: []
created_date: '2026-10-09 13:55'
labels:
  - ti-pki
  - tsl
  - spec
dependencies: []
references:
  - ti-pki/src/tsl.rs
priority: low
ordinal: 4000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
ZETA Guard keeps a certificate valid if its CA is revoked in the TSL but the certificate was issued before the CA's StatusStartingTime. ti-pki keeps only CAs in accord/granted and drops revoked CAs entirely. That was argued with an unauthenticated TSL; the TSL is now verified (spec/tsl-xmldsig), so decide whether to adopt the rule. Source: Obsidian note C_12791.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 decision recorded; if adopted, a certificate issued before StatusStartingTime under a revoked CA validates and one issued after does not
<!-- AC:END -->
