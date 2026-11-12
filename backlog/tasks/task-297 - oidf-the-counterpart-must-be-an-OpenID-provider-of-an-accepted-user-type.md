---
id: TASK-297
title: 'oidf: the counterpart must be an OpenID provider of an accepted user type'
status: To Do
assignee: []
created_date: '2026-11-12T21:08:00Z'
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
