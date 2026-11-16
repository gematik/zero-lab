---
id: TASK-352
title: >-
  pep/proxy: the PDP backend checks the authorization server's responses before
  use
status: To Do
assignee: []
created_date: '2026-11-16T22:52:00Z'
labels: []
dependencies: []
priority: medium
ordinal: 367000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
`pdpBackend` (`pep/proxy/backend_pdp.go`) reads metadata, providers, PAR, token and introspection responses without a `Content-Type` check, takes `token_type` and the token values unchecked, trims and keeps the nonce body without a grammar, puts AS error bodies (up to 1 MiB for PAR) raw into error text, and returns the AS's `Location` as the decoupled login URL unchecked, which the QR and authenticator pages assign to `window.location`. `openid.Response.CheckJSON` and `openid.ParseTokenResponse` already implement these checks. servers.md rule 28, "Outbound responses" and "Values". Found by the rule 28 audit of TASK-321 (2026-11-17).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 every AS response is refused unless its status and `Content-Type` are the expected ones; token responses go through the `openid` parser; the decoupled `Location` must be an https URI without user information; the nonce has a grammar and length.
- [ ] #2 AS error text in errors and logs is bounded and free of control characters; tests pin a `javascript:` Location and a non-JSON token response as refused.
<!-- AC:END -->
