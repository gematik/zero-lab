---
id: TASK-103.4
title: 'ti-cli: files and SQLite store backends'
status: To Do
assignee: []
created_date: '2026-10-15 17:45'
labels:
  - ti-cli
  - deps
dependencies:
  - TASK-103.3
parent_task_id: TASK-103
priority: medium
ordinal: 105000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
I/O backends as private ti-cli modules: files (sharded sealed files, STORE-6xx) and SQLite (STORE-5xx) via rusqlite with bundled, after maintainer approval of the dependency.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 rusqlite approved with transitive cost recorded
- [ ] #2 both backends pass the operation scenarios
- [ ] #3 100k-record load check within the recorded time budget
<!-- AC:END -->
