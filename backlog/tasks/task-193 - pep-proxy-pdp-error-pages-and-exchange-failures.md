---
id: TASK-193
title: 'pep/proxy, pdp: error pages and exchange failures'
status: To Do
assignee: []
created_date: '2026-11-02T22:59:00Z'
labels:
  - go
  - security
dependencies: []
priority: medium
ordinal: 203000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
pep/proxy error pages show err.Error(), including authorization server response bodies. pdp answers an exchange failure with JSON to the browser instead of redirecting to the client. verifyClient echoes client not found and jose details.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Clients and browsers see generic text; pdp redirects to the client
<!-- AC:END -->
