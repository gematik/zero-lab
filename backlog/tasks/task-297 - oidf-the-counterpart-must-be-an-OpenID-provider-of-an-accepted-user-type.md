---
id: TASK-297
title: 'oidf: a login only at an OpenID provider of a user type the caller accepts'
status: To Do
assignee: []
created_date: '2026-11-12T21:08:00Z'
updated_date: '2026-11-14T20:52:00Z'
labels: []
dependencies: []
ordinal: 313000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
relying_party.go has a TODO where the subject's entity type and user_type_supported should be checked before it is used as the provider of a login. Found by zeta-pdp-go, which needs it for the login of insured persons at a sektoral IDP (its TASK-54) or as named.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A login at an entity that is no openid_provider, or of a user type the caller does not accept, is refused
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
2026-11-14: TASK-315 refuses an IDP that is not on the master's IdP list (A_25449, the maintainer: only IDPs listed at the federation master are trusted) or has no openid_provider metadata. What is left here: a user-type filter, not built for now by the maintainer's decision.
<!-- SECTION:NOTES:END -->
