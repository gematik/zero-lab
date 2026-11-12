---
id: TASK-299
title: 'josebp: JWE decryption with ECDH-ES on brainpool curves'
status: To Do
assignee: []
created_date: '2026-11-12T21:08:00Z'
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
