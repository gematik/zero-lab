---
id: TASK-365
title: 'pep: a DPoP-bound access token is refused under the Bearer scheme'
status: In Progress
assignee: []
created_date: '2026-11-17T06:44:00Z'
updated_date: '2026-11-18T06:05:00Z'
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
- [ ] #1 The bearer enforcer refuses a token with a `cnf` member (`invalid_token`, 401). A test named after RFC 9449 §7.2 / RFC 9700 §4.10.1 proves it.
- [ ] #2 An `any_of` of bearer and DPoP still admits the DPoP-bound token with a valid proof.
<!-- AC:END -->
