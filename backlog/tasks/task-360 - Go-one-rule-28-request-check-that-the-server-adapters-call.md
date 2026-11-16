---
id: TASK-360
title: 'Go: one rule 28 request check that the server adapters call'
status: To Do
assignee: []
created_date: '2026-11-16T22:52:00Z'
labels: []
dependencies: []
priority: medium
ordinal: 375000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
go/docs/design.md section 10 names a helper that refuses a repeated `url.Values` key and `RawPath`/`EscapedPath` checks, yet no module has one (only `oidf/oidftest/idp.go:328-335`, a test IdP); pep/proxy, epa and zaddy each would write their own. servers.md rule 28, "One implementation, fuzzed". Found by the rule 28 audit of TASK-321 (2026-11-17).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 one package offers the single-value parameter read, the canonical-path check and the Host check, each with a `Fuzz…` target seeded with the rule's hostile inputs; the profile names it.
- [ ] #2 tasks 1, 2, 5, 7, 8 and 10 use it.
<!-- AC:END -->
