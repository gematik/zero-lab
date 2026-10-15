---
id: TASK-108
title: 'kv: doc comment names a nonexistent kvpg module'
status: To Do
assignee: []
created_date: '2026-10-15 17:45'
labels:
  - go
  - docs
  - chore
dependencies: []
priority: low
ordinal: 114000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
go/kv/kv.go package doc says the Postgres backend lives in a sibling kvpg module so importing kv never pulls a driver; it is the package kv/postgres inside the kv module, and kv/go.mod requires pgx. Either split the module or fix the comment.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 comment and module layout agree
<!-- AC:END -->
