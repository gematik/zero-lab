---
id: TASK-181
title: 'epa: providerNumber from the request selects the upstream host'
status: To Do
assignee: []
created_date: '2026-11-02T15:42:00Z'
labels:
  - go
  - security
dependencies: []
priority: medium
ordinal: 191000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
proxy.go forwards {providerNumber} after strconv.Atoi only, not against AllProviders as insurants.go does, and ResolveBaseURL builds the host from it, so a request can make the proxy reach epa-as-<any int>.<env>.epa4all.de and run a VAU handshake and SMC-B authorization there. The domain is fixed. Found by gosec G704 (TASK-86).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Only known providers are reachable, with a test, and the nolint lines naming this task are gone
<!-- AC:END -->
