---
id: TASK-353
title: >-
  pep: Bearer credentials and session cookies are bounded and parsed before
  verification
status: To Do
assignee: []
created_date: '2026-11-16T22:52:00Z'
labels: []
dependencies: []
priority: medium
ordinal: 368000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
`parseAuthorizationScheme` (`pep/pep.go:452-470`) accepts several `Authorization` headers and any string after the scheme, and `VerifyAccessToken` passes it to the JOSE parser without a size bound; the session cookie goes to `jose.ParseEncryptedCompact` unbounded (`pep/session_cookie.go:52-56`, and pep/proxy's `proxy.go:239`, `gateway_context.go:126`). The DPoP path already does this right (`dpop/authorization.go:37-55`). Both zaddy and zero-pep-proxy run these enforcers. servers.md rule 28, "Headers", "Bodies" (JWS/JWE size and compact form) and "Cookies". Found by the rule 28 audit of TASK-321 (2026-11-17).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 a request with more than one `Authorization` header, a credential that is not token68, or a token or cookie above a stated size is refused before any JOSE parsing.
- [ ] #2 a fuzz target over the Authorization parsing and one through an enforcer's `Apply` assert that a refused request never reaches `next`.
<!-- AC:END -->
