---
id: TASK-235
title: 'ti probe: live table taller than the terminal floods the scrollback'
status: To Do
assignee: []
created_date: '2026-11-06T16:59:00Z'
labels:
  - ti-cli
  - ux
dependencies: []
priority: medium
ordinal: 251000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Reported by the maintainer: scrolling up during ti probe shows many repeated lines. output/live.rs redraws the whole block every 100 ms by moving the cursor up by the block's height; when the block (header, groups, discovered catalog endpoints) is taller than the terminal, the cursor stops at the top row and every redraw pushes the overflow into the scrollback again.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 a run whose table is taller than the terminal leaves the table once in the scrollback
- [ ] #2 nothing is redrawn when nothing changed
<!-- AC:END -->
