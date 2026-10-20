---
id: TASK-115
title: 'zero-epa: profiles and the store commands'
status: To Do
assignee: []
created_date: '2026-10-16 06:53'
labels:
  - zero-epa
  - store
  - parked
dependencies:
  - TASK-103.5
priority: low
ordinal: 121000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
zero-epa gains --profile and opens the profile's shared store (go/store with go/sqlitestore), and implements the spec/store section L commands with the same names and doctor JSON as ti. Split from TASK-103.7 and parked by the maintainer: zero-epa is left alone for now. Follows ti's design from TASK-103.5.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 zero-epa --profile opens the profile's store
- [ ] #2 zero-epa implements the same section L commands with the same names and doctor JSON as ti
<!-- AC:END -->
