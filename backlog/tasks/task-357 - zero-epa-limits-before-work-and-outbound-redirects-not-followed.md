---
id: TASK-357
title: 'zero-epa: limits before work, and outbound redirects not followed'
status: In Progress
assignee: []
created_date: '2026-11-16T22:52:00Z'
updated_date: '2026-11-22T09:41:00Z'
labels: []
dependencies:
  - TASK-360
priority: medium
ordinal: 372000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
`epa/cmd/zero-epa/cmd/proxy.go:97` sets only `ReadHeaderTimeout` and no `MaxHeaderBytes`; forwarded bodies have no `MaxBytesReader` and are buffered whole by `DumpRequest` (`epa/vau/channel.go:196-198`); no Host check. The Aktensystem client follows redirects (`epa/session.go:248-260`), and `GetRecordStatus`/`GetConsentDecisionInformation` never close their response bodies (`epa/information.go:34-84`). servers.md rule 28, "Limits before work" and "Outbound responses". Found by the rule 28 audit of TASK-321 (2026-11-17).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 the server has explicit header, body (the ePA document limit for forwarded bodies) and timeout bounds and a Host check; the outbound client refuses redirects; every response body is closed.
- [ ] #2 tests pin an oversized body, a redirecting Aktensystem and a foreign Host as refused.
<!-- AC:END -->
