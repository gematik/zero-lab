---
id: TASK-370
title: 'pep/proxy gateway: pep''s own cookies are not forwarded upstream'
status: To Do
assignee: []
created_date: '2026-11-17T06:45:00Z'
labels:
  - pep-proxy
  - security
dependencies: []
priority: low
ordinal: 385000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The gateway's `Rewrite` (`go/pep/proxy/gateway.go:171-205`) strips `Authorization` and the identity headers. It still forwards the `Cookie` header, including `__Host-ZERO-PEP-SID` and `-SNAP`. Those cookies are the credential of a BFF session that holds DPoP-bound tokens and their key, so a compromised upstream can ride the session (RFC 9700 §4.9, §4.13). Found by the RFC 9700 audit of TASK-259 (2026-11-17).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The gateway removes its own session and snapshot cookies from upstream requests and keeps the others. Test named after the requirement.
<!-- AC:END -->
