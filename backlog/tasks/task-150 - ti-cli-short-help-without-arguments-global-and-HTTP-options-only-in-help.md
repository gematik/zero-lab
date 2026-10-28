---
id: TASK-150
title: 'ti-cli: short help without arguments, global and HTTP options only in --help'
status: Done
assignee: []
created_date: '2026-10-28T17:16:00Z'
updated_date: '2026-10-28T17:27:00Z'
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
- [x] #1 ti, ti SUBCOMMAND and -h list the commands and the command's own options; global and HTTP options appear only with --help
- [x] #2 The short help ends with one line naming --help for the global and HTTP options
- [x] #3 Tests pin the short and the long help; README and AGENTS.md need no change or are updated
<!-- AC:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
The shared options (--format, --color, -v, --profile, --cache-dir, the HTTP options, and the Konnektor options except -c) are hidden from the short help (hide_short_help); every command's short help ends with 'The options every command shares: --help', the long help lists them all and keeps the root's examples. ti without arguments now shows the help also when a TI_ variable such as TI_FORMAT or TI_CACHE_DIR is set: clap counted the env value as an argument and printed only 'requires a subcommand'; a missing subcommand now prints the short help of the deepest command named (exit 2). ti: 38 → 24 lines, ti directory login: 26 → 15. No pager (ti never prompts). Tests: short_help_leaves_the_shared_options_to_long_help, long_help_lists_the_shared_options. README and AGENTS.md needed no change. just check green.
<!-- SECTION:FINAL_SUMMARY:END -->
