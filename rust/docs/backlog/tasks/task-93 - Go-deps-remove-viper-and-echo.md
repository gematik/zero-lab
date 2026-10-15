---
id: TASK-93
title: 'Go deps: remove viper and echo'
status: To Do
assignee: []
created_date: '2026-10-14 20:44'
labels:
  - go
  - deps
  - epa
  - pdp
dependencies: []
references:
  - docs/conventions/dependencies.md
  - go/docs/design.md
priority: medium
ordinal: 91000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
viper and echo bring about 40 modules into epa and pdp.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 flags plus os.Getenv in cmd/ instead of viper, http.ServeMux instead of echo
<!-- AC:END -->
