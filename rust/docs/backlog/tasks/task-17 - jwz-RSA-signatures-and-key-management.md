---
id: TASK-17
title: 'jwz: RSA signatures and key management'
status: To Do
assignee: []
created_date: '2026-10-10 05:58'
labels:
  - jwz
dependencies:
  - TASK-12
priority: low
ordinal: 17000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The rsa feature is reserved and refuses to build (jwz-rsa-guard); the JWK RSA data model exists. Needs the rsa crate out of its release candidate (TASK-12).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 RS256/PS256 in crypto-rustcrypto behind the rsa feature, with Wycheproof vectors
- [ ] #2 RSA-OAEP(-256) decision recorded (implement or keep refused)
- [ ] #3 jwz-rsa-guard replaced by tests; strict profile unchanged
<!-- AC:END -->
