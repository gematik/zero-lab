---
id: TASK-446
title: 'Servers: the start check of secret file modes (servers.md rule 27)'
status: To Do
assignee: []
created_date: '2026-11-27T06:21:00Z'
labels: []
dependencies: []
ordinal: 455000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Rule 27 now says a server refuses a secret file that group or others can write, and warns when others can read it. No server checks this yet: zero-pep-proxy (session store key, TLS keys, client keys), hsm-proxy, the kv key files the hosts read. One helper in a shared Go module, used where each command reads a secret file.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A secret file writable by group or others stops the start, naming file and mode
- [ ] #2 A secret file readable by others logs a warning naming file and mode
- [ ] #3 Tests named after rule 27 for both cases
<!-- AC:END -->
