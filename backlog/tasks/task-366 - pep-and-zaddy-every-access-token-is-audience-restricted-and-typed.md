---
id: TASK-366
title: 'pep and zaddy: every access token is audience-restricted and typed'
status: To Do
assignee: []
created_date: '2026-11-17T06:44:00Z'
labels:
  - pep
  - zaddy
  - security
  - oauth
dependencies: []
priority: medium
ordinal: 381000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
`validateClaims` checks `aud` only when a resource is configured (`go/pep/token.go:228`). `Builder.Build` (`go/pep/pep.go:80-127`) accepts a PEP without `Resource`, and zaddy's `resource` is optional (`go/zaddy/zaddy.go:51,86`). `TestVerifyAccessToken_AudienceOptional` (`go/pep/verify_test.go:35`) keeps that mode for "authorization-server use", which left with go/pdp. Nor is the JWT `typ` checked (RFC 9068 §4 `at+jwt`), so another JWT signed by a key in the set (an ID token) is taken for an access token. RFC 9700 §2.3 and §4.10.2: the RS MUST refuse a token not meant for it. Found by the RFC 9700 audit of TASK-259 (2026-11-17).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 `Build` refuses a PEP without a resource, and zaddy refuses a config without `resource`. Tests named after RFC 9700 §4.10.2.
- [ ] #2 A token whose `typ` is not `at+jwt` (or `application/at+jwt`) is refused, unless the operator opts in for an AS known to omit it. Test named after RFC 9068 §4.
- [ ] #3 `TestVerifyAccessToken_AudienceOptional` is replaced by a test that the audience is required.
<!-- AC:END -->
