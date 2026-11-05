---
id: TASK-194
title: Discovery endpoints and idpd's signed issuer
status: In Progress
assignee: []
created_date: '2026-11-02T22:59:00Z'
updated_date: '2026-11-05T18:30:00Z'
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
- [x] #1 Discovery endpoints are https; idpd and ti-idpd compare the issuer
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
openid refuses a non-https issuer and non-https endpoints in the document. idpd and ti-idpd compare the signed issuer with the base URL; discovery::parse takes the Idp, a breaking change of ti-idpd. Live issuers of production, reference and test equal their base URLs, checked 2026-11-05. An OIDC issuer over http, as a local setup might use, is now refused.
<!-- SECTION:NOTES:END -->
