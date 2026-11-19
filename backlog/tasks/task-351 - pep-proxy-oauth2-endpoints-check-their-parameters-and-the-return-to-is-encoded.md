---
id: TASK-351
title: >-
  pep/proxy: /oauth2/* endpoints check their parameters, and the return-to is
  encoded
status: Done
assignee: []
created_date: '2026-11-16T22:52:00Z'
updated_date: '2026-11-19 08:46'
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
- [x] #1 a repeated parameter, an unknown parameter on /oauth2/start and /oauth2/sign_in, an `rd` outside its grammar, an `idp_iss` not among the listed providers and a `scope` outside the configured scopes are refused with 400; the Caddyfile encodes the return-to for the query.
- [x] #2 a fuzz target over the parameter parsing and `sanitizeReturnTo` asserts that an accepted `rd` is a local path outside /oauth2 and that errors do not contain the input.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
parameters(r, known…) reads a query as the endpoint declares it: it has to decode, each parameter occurs at most once (httpguard.Single), and for /oauth2/start (rd, idp_iss, scope) and /oauth2/sign_in (rd) no other name occurs; the callback takes the identity provider's response, so there only a repeated parameter is refused. checkReturnTo replaces sanitizeReturnTo and refuses instead of emptying; it also refuses a backslash and a control character anywhere (a browser reads '/<tab>/host' as '//host') and more than 2048 bytes. idp_iss has to be an issuer of Backend.Providers. scope: a backend lists its configured scopes (scopeLister, the PDP backend's cfg.Scopes) and every requested token has to be one of them; a backend that takes no scope allows none. Every refusal is the same 400 page, naming neither parameter nor value. Caddyfile: rd={http.request.uri_escaped} (in Caddy's replacer, checked in v2.11.7's source). Tests TestServerRule28_TheLoginEndpointsRefuseWhatTheyDoNotDeclare, …_AScopeIsRefusedWhereTheBackendTakesNone, TestRFC6749_3_1_TheCallbackRefusesARepeatedParameterAndIgnoresAnUnknownOne, TestRFC9700_4_11_1_TheReturnToIsALocalPathOfTheApplication, TestServerRule28_TheCaddyfileEncodesTheReturnToForTheQuery; FuzzCheckReturnTo (20 s, 0.8 million executions) and FuzzLoginStart (30 s, 0.9 million), no finding. Rollout: a deployment with its own Caddyfile or ingress rule has to encode rd the same way, or a request URI with a query is refused at /oauth2/start instead of starting a login.
<!-- SECTION:NOTES:END -->
