---
id: TASK-296
title: 'oidf: scopes and acr per login, typed claims of the ID token'
status: To Do
assignee: []
created_date: '2026-11-12T21:08:00Z'
labels: []
dependencies: []
ordinal: 312000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
AuthenticationURL sends fixed scopes and a hard-coded acr_values (client.go); Exchange returns the raw claims. A caller cannot ask for another acr or scope, and nothing checks the acr of the ID token or extracts the KVNR (urn:telematik:claims:id), the display name, acr and amr into a type. Found by zeta-pdp-go, which needs it for the login of insured persons at a sektoral IDP (its TASK-54) or as named.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Scopes and acr are parameters of a login; the result is a typed identity; an ID token with a lower acr than asked is refused
<!-- AC:END -->
