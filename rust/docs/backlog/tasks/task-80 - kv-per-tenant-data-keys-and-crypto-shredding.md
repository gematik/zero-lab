---
id: TASK-80
title: 'kv: per-tenant data keys and crypto-shredding'
status: To Do
assignee: []
created_date: '2026-10-14 20:44'
labels:
  - go
  - kv
  - privacy
dependencies: []
references:
  - go/docs/design.md
priority: medium
ordinal: 78000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
No per-tenant data keys (server rule 19).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 data encrypted per tenant or person under a key wrapped by the key service; deleting the key makes the data unreadable, backups included
<!-- AC:END -->
