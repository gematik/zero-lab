---
id: TASK-407
title: 'Go: the egress client behind a forward proxy (rule 30), on demand'
status: To Do
assignee: []
created_date: '2026-11-22 12:22'
labels:
  - go
  - servers
dependencies:
  - TASK-384
references:
  - docs/design/servers.md
priority: low
ordinal: 420000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Split from TASK-384 (2026-11-22, maintainer): the egress client honours HTTPS_PROXY, HTTP_PROXY and NO_PROXY, https through CONNECT only, no extra CA for egress, proxy credentials from a *_PATH file (a proxy URL with user information is refused), and the proxy in effect reported (rule 7). No deployment of ours uses a forward proxy today; build it when an operator requires one.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The egress client of TASK-384 goes through a forward proxy as rule 30 says, with tests for CONNECT, refused user information in the URL and NO_PROXY
<!-- AC:END -->
