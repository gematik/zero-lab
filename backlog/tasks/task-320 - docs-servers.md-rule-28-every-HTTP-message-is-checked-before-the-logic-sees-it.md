---
id: TASK-320
title: >-
  docs: servers.md rule 28, every HTTP message is checked before the logic sees
  it
status: In Progress
assignee: []
created_date: '2026-11-14T21:07:00Z'
updated_date: '2026-11-14T21:07:00Z'
labels:
  - docs
  - servers
dependencies: []
ordinal: 335000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The maintainer asked (2026-11-14) for the rules of checking HTTP requests in servers.md. Rule 2 names strict input handling in one line; what it means for an HTTP request (method, path, query, headers, body, values, cookies, redirects, errors) and for the responses of outbound calls is not written down, and TASK-315 step 5b implements it for oidf. New rule 28 at the end so cited numbers stay stable; the count in CLAUDE.md becomes 28.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 servers.md has rule 28 with the checks for inbound requests and outbound responses, fuzzing of the checks, and reject-never-repair
- [ ] #2 CLAUDE.md and any other count of the rules say 28
<!-- AC:END -->
