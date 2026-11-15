---
id: TASK-328
title: 'oidf: a login only at an IDP of a user type the caller accepts'
status: To Do
assignee: []
created_date: '2026-11-15T09:05:00Z'
labels:
  - oidf
  - go
dependencies: []
ordinal: 343000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Since TASK-315 an IDP is admitted only if it is on the master's signed IdP list and its statement has openid_provider metadata (the maintainer: only IDPs listed at the federation master are trusted). Not built: a filter by user type (the IdP list's user_type_supported, IP/HP/HCI), so a caller that serves insured persons only could refuse an IDP for health professionals before the login starts. The IdP list parser reads user_type_supported as a string or a one-element list and leaves anything else empty, which is harmless only while there is no filter. Replaces the user-type part of TASK-297; build it when a caller asks for it.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A caller can name the user types it accepts; a login at an IDP of another user type is refused before any request to the IDP
<!-- AC:END -->
