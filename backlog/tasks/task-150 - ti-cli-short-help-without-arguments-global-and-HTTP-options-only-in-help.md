---
id: TASK-150
title: 'ti-cli: short help without arguments, global and HTTP options only in --help'
status: To Do
assignee: []
created_date: '2026-10-28T17:16:00Z'
labels:
  - ti-cli
  - cli
milestone: m-0
dependencies: []
priority: medium
type: enhancement
ordinal: 158000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
ti without arguments, ti SUBCOMMAND and -h print the global and HTTP options under every command (38 lines for ti, 26 for ti directory login, most of them the same options), which hides what the command does. Show the commands and the command's own options there, hide the global and HTTP options from the short help (clap's hide_short_help) and point to --help, which keeps the full list. No pager: ti never prompts and must stay scriptable.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 ti, ti SUBCOMMAND and -h list the commands and the command's own options; global and HTTP options appear only with --help
- [ ] #2 The short help ends with one line naming --help for the global and HTTP options
- [ ] #3 Tests pin the short and the long help; README and AGENTS.md need no change or are updated
<!-- AC:END -->
