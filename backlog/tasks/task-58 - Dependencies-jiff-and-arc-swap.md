---
id: TASK-58
title: 'Dependencies: jiff and arc-swap'
status: To Do
assignee: []
created_date: 2026-10-14 20:43
updated_date: '2026-10-26T15:44:00Z'
labels:
  - ti-cli
  - ti-pki
  - deps
milestone: m-0
dependencies: []
references:
  - docs/conventions/dependencies.md
  - rust/docs/design.md
priority: medium
ordinal: 56000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
jiff only renders local time in CLI output; arc-swap has one use in ti-pki's reloader.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 jiff dropped (UTC output) or kept with a recorded reason; arc-swap replaced by a std lock or kept with measurements (performance before size)
<!-- AC:END -->
