---
id: TASK-293
title: >-
  oidf: entity statements, signed JWKS and the IDP list are cached until they
  expire
status: To Do
assignee: []
created_date: '2026-11-12T21:08:00Z'
labels: []
dependencies: []
ordinal: 309000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Every Provider() call fetches the master's statement, the provider's statement and its JWKS again (relying_party.go), and FetchIdpList goes to the network on each call. A login therefore costs several requests to the federation, and an outage of the master stops every login. Found by zeta-pdp-go, which needs it for the login of insured persons at a sektoral IDP (its TASK-54) or as named.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Within their validity statements, keys and list come from a cache that replicas can share; an expired entry is fetched again
<!-- AC:END -->
