---
id: TASK-94
title: 'Go deps: explicit Validate methods instead of go-playground/validator'
status: To Do
assignee: []
created_date: '2026-10-14 20:44'
labels:
  - go
  - deps
  - pdp
dependencies: []
references:
  - go/docs/design.md
priority: medium
ordinal: 92000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
validator works by reflection over about 67 struct tags and brings about 20 modules; explicit methods are easier to review for the authorization server.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 validator removed; request types validate themselves explicitly with tests per rule
<!-- AC:END -->
