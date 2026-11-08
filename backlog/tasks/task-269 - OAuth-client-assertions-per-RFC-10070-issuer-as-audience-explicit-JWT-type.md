---
id: TASK-269
title: 'OAuth client assertions per RFC 10070: issuer as audience, explicit JWT type'
status: To Do
assignee: []
created_date: '2026-11-08T09:35:00Z'
labels:
  - oauth
  - zeta
  - security
  - go
  - rust
dependencies: []
ordinal: 285000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
RFC 10070 (2026-11-07, https://www.rfc-editor.org/rfc/rfc10070.html) updates RFC 7521, 7522, 7523 and 9126. The audience of a client authentication JWT or an assertion grant was ambiguous: a malicious authorization server could name a legitimate server's token endpoint as audience and replay the client's JWT there (found in formal analysis of OpenID Federation). Now the audience is the authorization server's issuer identifier (RFC 8414) only, token endpoint URLs are no longer valid, and client authentication JWTs are typed client-authentication+jwt. OpenID Connect Core, FAPI 2.0, CIBA and OpenID Federation follow. Applies to the coming OAuth 2.0 / ZETA implementation and to what exists: go/pdp/authzserver verifies client assertions (client_assertion.go, token.go), go/pep/proxy creates them (backend_pdp.go). Read the RFC text for the exact rules (transition, PAR per RFC 9126) before changing code. Related: TASK-259 (RFC 9700), TASK-258 (RFC 8725).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 clients send the authorization server's issuer identifier as the only audience and type the JWT client-authentication+jwt
- [ ] #2 servers accept only their issuer identifier as audience and check the type as the RFC prescribes, with tests named after the RFC's requirements
- [ ] #3 the ZETA / OAuth 2.0 design in Rust follows the RFC from the start
<!-- AC:END -->
