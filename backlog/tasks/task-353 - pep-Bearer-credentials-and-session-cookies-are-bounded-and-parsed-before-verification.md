---
id: TASK-353
title: >-
  pep: Bearer credentials and session cookies are bounded and parsed before
  verification
status: Done
assignee: []
created_date: '2026-11-16T22:52:00Z'
updated_date: '2026-11-19 08:46'
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
- [x] #1 a request with more than one `Authorization` header, a credential that is not token68, or a token or cookie above a stated size is refused before any JOSE parsing.
- [x] #2 a fuzz target over the Authorization parsing and one through an enforcer's `Apply` assert that a refused request never reaches `next`.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Bearer: bearerCredentials replaces parseAuthorizationScheme: exactly one Authorization header, the scheme compared case-insensitively, one or more spaces, token68 credentials of at most maxAccessTokenBytes (16 KiB); anything else is 400 invalid_authorization_header before a token is parsed, while a well-formed credential that is no valid token stays 401 invalid_token. checkCompact (size, number of segments, base64url without padding, which segment is empty) runs in verifyJWS, so the DPoP path is bounded too, and in OpenSessionCookie (4096 bytes, five segments, no encrypted key), which pep's enforcer, pep/proxy's snapshot gate and its snapshotter all call. dpop exports IsToken68 for this (was isToken68): pep may import only dpop besides itself (mod-check), so the check could not go to httpguard. Tests TestServerRule28_BearerCredentialsAreCheckedBeforeATokenIsParsed, …_ATokenIsCheckedAgainstCompactFormAndSizeBeforeItIsDecoded, …_ASessionCookieIsBoundedAndCheckedBeforeItIsOpened; FuzzBearerCredentials and FuzzBearerEnforcer (20 s each, about 2.2 million executions each, no finding).
<!-- SECTION:NOTES:END -->
