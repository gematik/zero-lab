---
id: TASK-386
title: 'Go: DATABASE_URL carries its component''s prefix'
status: To Do
assignee: []
created_date: '2026-11-18 21:34'
labels:
  - pep-proxy
  - go
  - config
dependencies: []
references:
  - docs/conventions/naming-and-config.md
priority: low
ordinal: 400000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
zero-pep-proxy (go/pep/proxy/cmd/zero-pep-proxy/main.go:134, 160) and zero-pdp (go/pdp/cmd/zero-pdp/start.go:136) read their Postgres peer from DATABASE_URL. naming-and-config.md asks every variable to carry the prefix of the component that reads it, and the transport scheme (TASK-382) names a peer <COMPONENT>_<NAME>_URL. Found while writing TASK-382. go/pdp is frozen (decision-19), so this concerns zero-pep-proxy.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 zero-pep-proxy reads its store peer from a variable with its prefix, and its documentation says so
<!-- AC:END -->
