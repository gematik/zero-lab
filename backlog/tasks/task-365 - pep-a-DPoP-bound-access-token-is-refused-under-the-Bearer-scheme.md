---
id: TASK-365
title: 'pep: a DPoP-bound access token is refused under the Bearer scheme'
status: In Progress
assignee: []
created_date: '2026-11-17T06:44:00Z'
updated_date: '2026-11-18T06:12:00Z'
labels:
  - pep
  - security
  - oauth
dependencies: []
priority: high
ordinal: 380000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
`EnforcerAuthorizationBearer` (`go/pep/enforcers.go:297-316`) → `verifyAuthorizationBearer` (`go/pep/pep.go:359-374`) accepts any verified JWT, including one whose `cnf.jkt` binds it to a DPoP key (`token.go:62-75`). A leaked DPoP-bound token can therefore be replayed without a proof at any `authorization_bearer` route of the same PEP (zaddy `enforce_policy.go:104-108`; the shipped `zaddy/Caddyfile` has both schemes). That voids sender-constraining (RFC 9700 §2.2.1, §4.10.1; RFC 9449 §7.2). Found by the RFC 9700 audit of TASK-259 (2026-11-17).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 The bearer enforcer refuses a token with a `cnf` member (`invalid_token`, 401). A test named after RFC 9449 §7.2 / RFC 9700 §4.10.1 proves it.
- [x] #2 An `any_of` of bearer and DPoP still admits the DPoP-bound token with a valid proof.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Branch fix/rfc9700-gaps, commit e95951fc. AccessToken.Bound(): a cnf member of any confirmation method (or a payload that does not decode) makes the token sender-constrained; verifyAuthorizationBearer refuses it with 401 invalid_token under the Bearer challenge, and puts no claims on the context, so a later enforcer of an any_of never sees them. Tests: TestRFC9449_7_2_RFC9700_4_10_1_ABoundTokenIsRefusedUnderTheBearerScheme (jkt and x5t#S256; fails without the check), TestRFC9449_7_1_AnyOfBearerAndDPoPAdmitsABoundTokenWithItsProof. zaddy tests pass unchanged.
<!-- SECTION:NOTES:END -->
