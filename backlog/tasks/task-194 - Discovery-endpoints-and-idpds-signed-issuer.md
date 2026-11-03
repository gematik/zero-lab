---
id: TASK-194
title: Discovery endpoints and idpd's signed issuer
status: To Do
assignee: []
created_date: '2026-11-02T22:59:00Z'
updated_date: '2026-11-03T07:41:00Z'
labels:
  - go
  - security
dependencies: []
priority: medium
ordinal: 204000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
go/openid does not require discovery endpoints to be https. idpd does not compare the signed metadata's issuer with the base URL, and ti-idpd's discovery.rs appears not to either.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Discovery endpoints are https; idpd and ti-idpd compare the issuer
<!-- AC:END -->
