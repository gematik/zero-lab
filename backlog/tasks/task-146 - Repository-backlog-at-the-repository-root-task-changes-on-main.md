---
id: TASK-146
title: 'Repository: backlog at the repository root, task changes on main'
status: Done
assignee: []
created_date: '2026-10-26T11:52:00Z'
updated_date: '2026-10-26T11:53:00Z'
labels:
  - chore
  - docs
dependencies: []
priority: medium
ordinal: 155000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The backlog lives in backlog with rust/backlog.config.yml, although it holds work for the whole repository. Backlog.md resolves cross-branch task files relative to its project root but reads them with git show from the repository root, so every task whose newest version is on another branch fails to load ('Failed to hydrate task'), and the board exits when such a task scrolls into view. The idiomatic layout is backlog/ at the repository root with backlog/config.yml (Backlog.md's zero-configuration default). Tasks are changed on main, or on a branch that merges soon, so other branches need not be scanned.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 The backlog is in backlog/ at the repository root with backlog/config.yml; backlog and rust/backlog.config.yml are gone
- [x] #2 check_active_branches is off; board, list and search run without hydrate errors
- [x] #3 docs/conventions/backlog.md says where the backlog is, that backlog runs from the repository root, and that task changes go to main or to a branch that merges soon
- [x] #4 Every link to the old location (docs, CLAUDE.md, CONTRIBUTING.md, READMEs, tasks, decisions, spec) points to backlog/
<!-- AC:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Moved rust/docs/backlog to backlog/ and rust/backlog.config.yml to backlog/config.yml (Backlog.md's default layout, so backlog_directory is dropped), project name zero-lab, check_active_branches off. docs/conventions/backlog.md says where the backlog is and that task changes go to main or a soon-merging branch; git-and-releases.md links that exception. Paths updated in CLAUDE.md, CONTRIBUTING.md, docs/, go/docs/development.md, spec/store/README.md and task-24. Verified: every relative link in the changed documents resolves, backlog task list and search run from the root with no hydrate errors (18 before). The interactive board was not driven here.
<!-- SECTION:FINAL_SUMMARY:END -->
