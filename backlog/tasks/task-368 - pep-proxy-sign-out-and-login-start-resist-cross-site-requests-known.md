---
id: TASK-368
title: 'pep/proxy: sign-out and login start resist cross-site requests'
status: To Do
assignee: []
created_date: '2026-11-17T06:45:00Z'
updated_date: '2026-11-17T06:45:00Z'
labels:
  - pep-proxy
  - security
  - oauth
dependencies: []
priority: medium
ordinal: 383000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
`GET /oauth2/sign_out` (`go/pep/proxy/proxy.go:197,508-530`) ends the session without a CSRF check, so any site can sign a user out with a link or an image (logout CSRF; RFC 9700 §2.1 CSRF, RFC 6819 §4.4.1.8 class). Only POST requires `X-Requested-With` (test `TestServerRule2_SignOutByPOSTRequiresCSRFProtection`). Likewise a cross-site top-level `GET /oauth2/start` creates a pending session and overwrites the cookie of a signed-in browser (`proxy.go:343-354`). Found by the rule 28 audit and recorded in TASK-259's notes. Found by the RFC 9700 audit of TASK-259 (2026-11-17).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 GET `/oauth2/sign_out` only renders a confirmation page whose form POSTs with a per-session token (or `Sec-Fetch-Site: same-origin`). A cross-site request leaves the session intact. Test named after the requirement.
- [ ] #2 `/oauth2/start` does not replace an authenticated session's cookie on a cross-site request, or the decision to allow it is recorded with its reason.
<!-- AC:END -->
