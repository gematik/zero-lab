---
id: TASK-27
title: >-
  ti-idpd: verify puk_idp_sig/puk_idp_enc certificates and the discovery
  document against the TSL
status: To Do
assignee: []
created_date: '2026-10-10 15:04'
labels:
  - ti-idpd
  - ti-pki
dependencies: []
priority: medium
ordinal: 27000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The Go gemidp uses the IDP-Dienst keys with unverified certificates (a logged warning). gemSpec_IDP_Dienst requires the discovery document signature and the C.FD.SIG certificate (role oid_idpd 1.2.276.0.76.4.260) to be checked against the TSL with hourly OCSP. ti-pki already has the idp-sig profile. ti-idpd stage 2 carries the warning in the report; this task makes the check real: verify the discovery document JWS and puk_idp_sig's x5c with ti-pki (idp-sig, --env), cache the verdict for an hour, fail closed in enforce mode.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 ti idpd authenticate reports idp_discovery_verified: true against the RU IDP and fails with a distinct error kind on a tampered discovery document (fixture)
- [ ] #2 the warning entry disappears from the report; AGENTS.md documents the behaviour
<!-- AC:END -->
