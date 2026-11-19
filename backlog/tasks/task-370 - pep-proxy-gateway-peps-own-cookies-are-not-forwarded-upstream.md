---
id: TASK-370
title: 'pep/proxy gateway: pep''s own cookies are not forwarded upstream'
status: In Progress
assignee: []
created_date: '2026-11-17T06:45:00Z'
updated_date: '2026-11-19 08:29'
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
- [x] #1 The gateway removes its own session and snapshot cookies from upstream requests and keeps the others. Test named after the requirement.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
The gateway's Rewrite removes the cookies this server sets from the Cookie fields it forwards (withoutCookies: every other cookie-pair stays as received, in order; a field left empty is dropped). The server hands the gateway both names, the session cookie's and the snapshot's, also when no snapshot is in use. Tests TestRFC9700_4_9_TheGatewayForwardsNoneOfItsOwnCookies and …_TheServersGatewayKnowsBothOfItsCookies.
<!-- SECTION:NOTES:END -->
