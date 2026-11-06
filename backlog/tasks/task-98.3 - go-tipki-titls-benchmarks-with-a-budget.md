---
id: TASK-98.3
title: go/tipki/titls benchmarks with a budget
status: To Do
assignee: []
created_date: '2026-11-06T14:01:00Z'
labels:
  - go
  - security
dependencies: []
parent_task_id: TASK-98
ordinal: 246000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Cold and cached verification per profile with TASK-97's budgets (5 ms cold, 10 µs cached), checked by a just recipe in go/.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 a just recipe fails when a budget is exceeded
<!-- AC:END -->
