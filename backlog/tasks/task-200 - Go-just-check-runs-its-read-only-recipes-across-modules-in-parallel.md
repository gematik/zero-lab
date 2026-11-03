---
id: TASK-200
title: 'Go: just check runs its read-only recipes across modules in parallel'
status: In Progress
assignee: []
created_date: '2026-11-03 13:02'
labels:
  - go
  - chore
dependencies: []
references:
  - go/Justfile
  - docs/conventions/git-and-releases.md
priority: low
ordinal: 201000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
just check in go/ runs seven passes over 15 modules, one module after another: about 12 minutes on warm caches, 15 after a merge. mod-check (357s) and test-race (177s) are two thirds of that. Running the read-only recipes in parallel takes the same checks to about 6.5 minutes, with no check dropped or weakened. golangci-lint refuses a second instance, so it stays sequential, as do tidy, upgrade and modernize-fix, which write files.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 just check runs lint, modernize, vuln, mod-check, test and test-race across modules in parallel, at most EACH_JOBS at a time, default 4
- [ ] #2 EACH_JOBS=1 runs modules one after another
- [ ] #3 output is printed per module in module order at any setting
- [ ] #4 a failing module fails the recipe, and every module still runs
- [ ] #5 golangci, tidy, upgrade and modernize-fix run one module at a time
<!-- AC:END -->
