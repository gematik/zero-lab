---
id: TASK-200
title: 'Go: just check runs its read-only recipes across modules in parallel'
status: In Progress
assignee: []
created_date: '2026-11-03 13:02'
updated_date: '2026-11-03 13:08'
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
- [x] #1 just check runs lint, modernize, vuln, mod-check, test and test-race across modules in parallel, at most EACH_JOBS at a time, default 4
- [x] #2 EACH_JOBS=1 runs modules one after another
- [x] #3 output is printed per module in module order at any setting
- [x] #4 a failing module fails the recipe, and every module still runs
- [x] #5 golangci, tidy, upgrade and modernize-fix run one module at a time
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Measured on warm caches: 714s summed over the recipes at one job, 392s and 350s for just check at the default of 4 (mod-check 357s to 115s, test-race 177s to 111s). 6 jobs was not measured, so 4 is a reasonable default rather than a proven best. Failure handling was tried with a command failing in kv: all 15 modules ran, order kept, exit 1. Why mod-check is this slow is not explained. Tests passed in every run at 4 jobs, too few to rule out a timing-sensitive test under -race; EACH_JOBS=1 is the first thing to try if one appears. just check green on this branch; api-lint skipped, no ruleset configured.
<!-- SECTION:NOTES:END -->
