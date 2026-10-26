---
id: TASK-75
title: SSRF review of outbound fetches in oidf and oauth
status: To Do
assignee: []
created_date: '2026-10-14 20:44'
labels:
  - go
  - oidf
  - oauth
  - security
dependencies: []
references:
  - docs/design/servers.md
  - go/docs/design.md
priority: medium
ordinal: 73000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
oidf.FetchEntityStatement(iss) and the oauth fetches take URLs derived from input (server rule 2).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 one outbound HTTP constructor with allowlist, private and link-local ranges blocked after DNS resolution, no cross-host redirects, timeouts and size limits, used by oidf and oauth
<!-- AC:END -->
