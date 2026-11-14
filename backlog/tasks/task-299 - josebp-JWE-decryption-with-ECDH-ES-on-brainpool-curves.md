---
id: TASK-299
title: 'josebp: JWE decryption with ECDH-ES on brainpool curves'
status: Done
assignee: []
created_date: '2026-11-12T21:08:00Z'
updated_date: '2026-11-14T20:52:00Z'
labels: []
dependencies: []
ordinal: 315000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
josebp encrypts ECDH-ES JWE on brainpool curves and cannot decrypt one; go-jose, which oidf uses for the ID token, knows NIST curves only. Whether sektoral IDPs encrypt ID tokens to brainpool keys is not confirmed: check the federation's specification first, and close this task if they do not. Found by zeta-pdp-go, which needs it for the login of insured persons at a sektoral IDP (its TASK-54) or as named.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 It is known whether the federation uses brainpool for ID token encryption; if so, josebp decrypts it
<!-- AC:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Closed as not needed: the relying party keys of a ZETA guard are P-256 (as-entity-statement.yaml of gemSpec_ZETA 2.0.0-1, ecP256Jwk), and keycloak-zeta uses P-256. Reopen if a sektoral IDP is found encrypting to a brainpool key.
<!-- SECTION:FINAL_SUMMARY:END -->
