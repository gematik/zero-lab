---
id: TASK-259
title: OAuth clients and servers checked against RFC 9700 (OAuth 2.0 Security BCP)
status: Done
assignee: []
created_date: '2026-11-07T18:04:00Z'
updated_date: '2026-11-17T06:45:00Z'
labels:
  - security
  - spec
  - go
  - rust
dependencies: []
references:
  - https://www.rfc-editor.org/rfc/rfc9700
  - docs/design/servers.md
priority: medium
type: task
ordinal: 275000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
RFC 9700 (January 2025) is the OAuth 2.0 Security Best Current Practice: PKCE for every client, no implicit and no resource-owner password grant, exact redirect URI matching, sender-constrained or rotated refresh tokens, audience-restricted access tokens, mix-up defence, no open redirectors, among others. The repo has OAuth/OIDC clients and servers (rust ti-idpd and ti-directory, go idpd, openid, oidf, pdp authorization server, pep proxy), and none is traced against it.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 each RFC 9700 §2 and §4 requirement that applies to a client or server here is listed per component with the code or test that meets it, or recorded as not applicable with the reason
- [x] #2 each gap becomes its own task
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
2026-11-17: go/pdp is out of scope; zeta-pdp-go replaces zero-pdp (decision in memory: basics are cherry-picked into zeta-pdp-go). Its authorization server is checked there.

Found by the rule 28 audit (2026-11-17): GET /oauth2/sign_out in zero-pep-proxy lets another site sign a user out (logout CSRF, RFC 9700); belongs here.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
RFC 9700 §2 and §4 checked per component (pep/proxy, pep, zaddy, openid, oidf, idpd, epa, dpop/nonce, ti-idpd-client, ti-directory-client) in doc-6, each requirement met with file:line or test, a gap, or n/a with the reason; go/pdp out of scope (zeta-pdp-go). Gaps became tasks: 364 (callback in the starting browser), 365 (DPoP-bound token refused as Bearer), 366 (audience required, at+jwt), 367 (mix-up defence, RFC 9207), 368 (sign-out/start CSRF), 369 (callback Referrer-Policy, state once), 370 (gateway strips pep cookies), 371 (openid private_key_jwt), 372 (Authenticator origin). Existing: 351, 352, 353, 359; 310 fixed; 269 not applicable.
<!-- SECTION:FINAL_SUMMARY:END -->
