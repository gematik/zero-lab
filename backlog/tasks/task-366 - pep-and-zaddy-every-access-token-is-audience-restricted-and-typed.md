---
id: TASK-366
title: 'pep and zaddy: every access token is audience-restricted and typed'
status: Done
assignee: []
created_date: '2026-11-17T06:44:00Z'
updated_date: '2026-11-22 14:48'
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
- [x] #1 `Build` refuses a PEP without a resource, and zaddy refuses a config without `resource`. Tests named after RFC 9700 §4.10.2.
- [x] #2 A token whose `typ` is not `at+jwt` (or `application/at+jwt`) is refused, unless the operator opts in for an AS known to omit it. Test named after RFC 9068 §4.
- [x] #3 `TestVerifyAccessToken_AudienceOptional` is replaced by a test that the audience is required.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
2026-11-22: zeta-pdp-go signs its access tokens with typ at+jwt (pdp/pdp.go typAccessToken); go/pdp (frozen) signs typ JWT and sets no aud, so the e2e setup 'PDP backend S4' (zaddy behind the PDP) is refused by zaddy since this change even with accept_untyped_access_tokens. Keycloak's typ was not checked: a deployment behind keycloak-zeta may need accept_untyped_access_tokens.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
pep.Builder.Build refuses a PEP without Resource (RFC 9700 Section 4.10.2), and VerifyAccessToken refuses a token whose typ is not at+jwt or application/at+jwt, compared without case (RFC 9068 Section 4), unless the host calls AcceptUntypedAccessTokens. zaddy: Validate refuses a pep block without resource; accept_untyped_access_tokens is the operator's opt-in; README section 'Access tokens'. Tests: TestRFC9700_4_10_2_TheAudienceIsRequired (replaces TestVerifyAccessToken_AudienceOptional), TestRFC9068_4_ATokenOfAnotherTypIsRefused, TestRFC9068_4_AnUntypedTokenIsTakenOnlyByOptIn, TestRFC9700_4_10_2_ZaddyRefusesAConfigurationWithoutAResource; the legacy verdict fixture lists the five cases newly refused for lacking aud. Breaking for pep and zaddy at the next release.
<!-- SECTION:FINAL_SUMMARY:END -->
