---
id: TASK-351
title: >-
  pep/proxy: /oauth2/* endpoints check their parameters, and the return-to is
  encoded
status: To Do
assignee: []
created_date: '2026-11-16T22:52:00Z'
updated_date: '2026-11-16T22:52:00Z'
labels: []
dependencies:
  - TASK-360
priority: medium
ordinal: 366000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
`handleStart`, `handleSignIn` and `handleCallback` (`pep/proxy/proxy.go:310-494`) take the first of a repeated parameter, ignore unknown ones on these own endpoints, repair a refused `rd` to "" and, with the PDP backend, pass `scope` and `idp_iss` from the query to the authorization server unchecked (`backend_pdp.go:355-372`). The shipped forward_auth Caddyfile (`cmd/zero-pep-proxy/Caddyfile:31`) puts the original URI into `rd=` unencoded, so a request URI can add `idp_iss`/`scope` parameters. servers.md rule 28, "Parameters" and "Redirects". Found by the rule 28 audit of TASK-321 (2026-11-17).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 a repeated parameter, an unknown parameter on /oauth2/start and /oauth2/sign_in, an `rd` outside its grammar, an `idp_iss` not among the listed providers and a `scope` outside the configured scopes are refused with 400; the Caddyfile encodes the return-to for the query.
- [ ] #2 a fuzz target over the parameter parsing and `sanitizeReturnTo` asserts that an accepted `rd` is a local path outside /oauth2 and that errors do not contain the input.
<!-- AC:END -->
