---
id: TASK-235
title: 'ti probe: live table taller than the terminal floods the scrollback'
status: In Progress
assignee: []
created_date: '2026-11-06T16:59:00Z'
updated_date: '2026-11-06T17:04:00Z'
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
- [x] #1 a run whose table is taller than the terminal leaves the table once in the scrollback
- [x] #2 nothing is redrawn when nothing changed
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
On fix/probe-live-fit (worktree ../zero-lab-probe-fit, 542857a9): Live reads the window height once from stty size on /dev/tty (fallback 24, no dependency), draws at most height-1 lines, skips a redraw equal to the screen; probe shows heading + running probes + 'n of m done' when the table does not fit, the whole table at the end. Proof by hand pending: run ti probe in a short window and scroll up.
<!-- SECTION:NOTES:END -->
