---
id: TASK-406
title: 'oidf: oidftest as a module of its own'
status: To Do
assignee: []
created_date: '2026-11-22 11:42'
labels:
  - oidf
  - go
  - testing
dependencies: []
priority: low
ordinal: 419000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
go/oidf/oidftest (about 1,070 lines: a fake federation master and IDP with gemSpec_IDP_Sek defaults) is a test-support package inside the oidf module, a fifth of its code. Every consumer of oidf gets it in the module it pins, though only tests import it (oidf 3 files, pdp 3, pep/proxy 1; just mod-check refuses a non-test importer). As go/oidftest (or go/oidf/oidftest with its own go.mod) it is versioned on its own, oidf's tagged code shrinks to what runs, and a change to the fake no longer needs an oidf release. Found 2026-11-22 when looking at oidf's growth since v0.52.0 (TASK-315).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 oidftest is its own Go module with its own go.mod, in go.work, tagged like any unit; oidf no longer contains it
- [ ] #2 oidf's own tests, pdp and pep/proxy import it from the new module; just mod-check still refuses a non-test importer
- [ ] #3 just sync pins it; just check passes; ReleaseNotes record the move for oidf and the new module
<!-- AC:END -->
