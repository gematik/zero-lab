---
id: TASK-406
title: 'oidf: oidftest as a module of its own'
status: In Progress
assignee: []
created_date: '2026-11-22 11:42'
updated_date: '2026-11-22 12:07'
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
- [x] #2 oidf's own tests, pdp and pep/proxy import it from the new module; just mod-check still refuses a non-test importer
- [ ] #3 just sync pins it; just check passes; ReleaseNotes record the move for oidf and the new module
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
2026-11-22: go/oidftest is a module of its own (github.com/gematik/zero-lab/go/oidftest), in go.work, beside oidf rather than nested: a nested go/oidf/oidftest is an ambiguous import against every oidf version that still holds the package. oidf's login tests (login_test.go) moved with it, as they test oidf against the test federation and would otherwise make oidf require oidftest; the duplicate newKey helper went. pdp and pep/proxy require it (just sync pins it at the branch tip with oidf); the yaml-free lists of the Justfile and go/docs/design.md name it; mod-check's test-package rule still holds. Full just check green on c6d94d98. Open, by the maintainer's decision (no releases while findings are collected): the oidftest tag (AC #1) and the release notes (AC #3), with the next oidf release, which drops the package.
<!-- SECTION:NOTES:END -->
