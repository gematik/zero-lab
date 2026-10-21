---
id: TASK-127
title: 'Go: delete the bff in favour of pep'
status: To Do
assignee: []
created_date: '2026-10-21 07:14'
labels:
  - go
  - pep
  - chore
dependencies: []
priority: medium
ordinal: 138000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
pep is the bff generalized and meant to replace it (pep/proxy package doc; pep/proxy/docs/BACKLOG.md, 'goal: retire the bff'): it matches or exceeds the bff as AS client (PAR, DPoP-nonce retry), on sessions and on DPoP, and the bff has no consumers. The one blocker named there is gateway parity (S5: multi-route reverse proxy, identity-header injection, HTML/API branching), which CONFIG.md's gateway mode (PEP_ROUTES_PATH) may already cover. Check the parity, then: replace zero-bff-pdp with zero-pdp + zero-pep-proxy, repoint the justfile docker targets and compose files, delete go/bff and its module from go.work, update the module table in go/docs/development.md. Saves migrating the bff off jwx (TASK-95).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 gateway parity confirmed against pep/proxy/docs/BACKLOG.md item 1, gaps closed or filed
- [ ] #2 go/bff and zero-bff-pdp gone: go.work, justfile, compose, docs; the pdp e2e runs with zero-pdp and zero-pep-proxy
<!-- AC:END -->
