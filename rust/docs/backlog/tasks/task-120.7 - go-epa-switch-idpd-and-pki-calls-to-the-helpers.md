---
id: TASK-120.7
title: 'go/epa: switch idpd and pki calls to the helpers'
status: To Do
assignee: []
created_date: '2026-10-20 14:07'
updated_date: '2026-10-20 14:07'
labels:
  - go
  - epa
dependencies:
  - TASK-120.4
  - TASK-120.5
  - TASK-120.6
parent_task_id: TASK-120
priority: medium
ordinal: 132000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Waits for the maintainer's design of the ePA local setup (local test environment, local client, middleware in Docker). Then go/epa calls ti-idpd-helper for idpd authenticate and ti-pki-helper for pki verify and verify-signature, each started once per session as a stdio child through go/tirpc, instead of one ti process per call. identity inspect and sign stay on ti until a ti-identity-helper exists.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 design of the ePA local setup agreed with the maintainer
- [ ] #2 epa uses the helpers for idpd and pki
- [ ] #3 HITL of the ePA flow proven by the maintainer
<!-- AC:END -->
