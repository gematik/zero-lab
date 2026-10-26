---
id: TASK-27
title: >-
  ti-idpd: verify puk_idp_sig/puk_idp_enc certificates and the discovery
  document against the TSL
status: Done
assignee: []
created_date: '2026-10-10 15:04'
updated_date: '2026-10-11 06:16'
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
- [x] #1 ti idpd authenticate reports idp_discovery_verified: true against the RU IDP and fails with a distinct error kind on a tampered discovery document (fixture)
- [x] #2 the warning entry disappears from the report; AGENTS.md documents the behaviour
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Done 2026-10-11. ti-idpd: authenticate takes a trust::CertificateTrust and hands it the discovery signer (puk_disc_sig, x5c) and PuK_IDP_SIG's certificate (JWK x5c, key must match) before the card signs; refusal = Error::Untrusted. PuK_IDP_ENC has no certificate (trusted via the verified discovery document). ti-cli: TSL check with the idp-sig profile and OCSP in the --env environment (or detected from the certificate with --idp-url); report idp.certificates[{key, subject, sha256, verified}] instead of an idp_discovery_verified flag; error kind idpd_untrusted (exit 3); --idp-unverified keeps the old warning (loopback tests, reference implementations). A tampered discovery document stays a signature error (idpd_protocol). No hourly verdict cache: one TSL load and two OCSP requests per run, TSL from the cache. HITL: directory login (P12 SMC-B57 and SMC-B-7 at the Konnektor) and just epa-connect-test against RU, both certificates valid, no warning.
<!-- SECTION:NOTES:END -->
