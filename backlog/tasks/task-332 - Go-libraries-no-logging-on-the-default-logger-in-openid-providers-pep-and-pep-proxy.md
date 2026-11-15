---
id: TASK-332
title: >-
  Go libraries: no logging on the default logger in openid/providers, pep and
  pep/proxy
status: In Progress
assignee: []
created_date: '2026-11-15T09:53:00Z'
updated_date: '2026-11-15T14:51:00Z'
labels:
  - go
  - pep
  - openid
dependencies: []
ordinal: 347000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
go/docs/design.md section 2: a library logs only through a logger it was given. Found by the review of TASK-317: openid/providers/providers.go (~170, slog.Info configured openid provider), pep/pep.go (~91, 249, 265), pep/enforcers.go (~120, 135, 175), pep/proxy/gateway.go and render.go write to the default slog. oidf (TASK-322) and openid's client and key parsing (TASK-315, TASK-317) no longer do.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 No non-test library code in openid, pep and pep/proxy calls the default slog; a logger is handed in where one is needed, or the outcome is returned
<!-- AC:END -->
