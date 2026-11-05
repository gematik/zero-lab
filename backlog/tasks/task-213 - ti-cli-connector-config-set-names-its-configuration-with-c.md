---
id: TASK-213
title: 'ti-cli: connector config set names its configuration with -c'
status: Done
assignee: []
created_date: '2026-11-04T18:34:00Z'
updated_date: '2026-11-05T17:54:00Z'
labels:
  - ti-cli
  - cli
dependencies: []
priority: low
ordinal: 220000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
`ti connector config set NAME KEY=VALUE` takes the configuration as an argument, while the other connector commands take `-c NAME` and fall back to the selected configuration. Found by the maintainer while using it.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 `ti connector -c NAME config set KEY=VALUE` and `ti connector config set -c NAME KEY=VALUE` change configuration NAME
- [x] #2 Without -c it changes the selected configuration, as `config show` reads it, and reports the file it saved
- [x] #3 A NAME given the old way is refused with a message naming -c, and nothing changes
- [x] #4 README, AGENTS.md and the release notes show the new form
<!-- AC:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
connector config set takes its configuration from -c; a name given the old way is refused, naming -c. Merged in PR #85 (ebdd88b).
<!-- SECTION:FINAL_SUMMARY:END -->
