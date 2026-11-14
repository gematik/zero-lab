---
id: TASK-318
title: 'openid: the plain OIDC client checks the acr it asked for'
status: To Do
assignee: []
created_date: '2026-11-14T20:52:00Z'
labels:
  - openid
  - go
dependencies: []
ordinal: 333000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Since TASK-315 an openid.Login carries ACRValues, and AuthorizationQuery sends them to any provider, but only oidf checks the acr of the ID token it gets back. The plain OIDC client (openid/client.go) takes whatever acr comes (OIDC Core 3.1.2.1: acr_values are voluntary unless requested as essential through claims). Found while planning TASK-315.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 An ID token from the plain OIDC client with an acr other than one asked for is refused when ACRValues were set
<!-- AC:END -->
