---
id: TASK-235
title: 'ti probe: live table taller than the terminal floods the scrollback'
status: Done
assignee: []
created_date: '2026-11-06T16:59:00Z'
updated_date: '2026-11-06T18:55:00Z'
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
- [x] #1 the Bestandsnetze take one line in the probe's table, grouped by result, so production's table stays readable and fits the window
- [x] #2 -k checks no TLS certificate in the probe, answers stay judged as usual and say TLS not checked (-k), with one warning
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Maintainer's iterations: fit-to-window folding was tried and dropped (the layout jumped); final: old layout, Bestandsnetze always one line; -k reaches every probe endpoint, ePA included, and loads no TSL; one -k warning.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Merged 824788ad: ti probe puts the Bestandsnetze on one line (names by result, JSON keeps details); -k checks no certificate in the probe, answers stay green with 'TLS not checked (-k)' and tls.verified null, one warning; the download warning reads 'the TLS certificates of download servers are not checked'.
<!-- SECTION:FINAL_SUMMARY:END -->
