---
id: TASK-98.5
title: Every Go client on its profile
status: To Do
assignee: []
created_date: '2026-11-06T14:01:00Z'
labels:
  - go
  - security
dependencies: []
parent_task_id: TASK-98
ordinal: 248000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Inventory of Go clients and the endpoints they reach; epa proxy and probe verify under ti (closes TASK-229 and removes the TASK-180 nolint), internet clients under web, no fallback to unverified TLS.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 epa proxy and probe verify under ti
- [ ] #2 every other Go client of a TI or internet endpoint uses its profile
<!-- AC:END -->
