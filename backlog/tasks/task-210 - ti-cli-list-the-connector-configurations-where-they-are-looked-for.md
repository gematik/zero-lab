---
id: TASK-210
title: 'ti-cli: list the connector configurations where they are looked for'
status: Done
assignee: []
created_date: '2026-11-04T12:59:00Z'
updated_date: '2026-11-05T17:54:00Z'
labels:
  - ti-cli
  - cli
dependencies: []
priority: low
ordinal: 217000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
`ti connector configs` lists the .kon files, but it sits one level above `ti connector config` (show, test, new, edit, set, pin) and differs from it by one letter, so the maintainer looked for it there and concluded it was missing. `ti connector use` without a name only fails with a usage error, although the list is what one needs before choosing.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 `ti connector config list` lists the .kon files with the same output as `ti connector configs` did
- [x] #2 `ti connector configs` still works and is hidden from `--help`
- [x] #3 `ti connector use` without a name shows the list, exits 0 and changes no selection
- [x] #4 `ti connector use NAME` behaves as before
- [x] #5 README, AGENTS.md and the release notes name `connector config list`
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. Add `ConnectorConfig::List` running the existing listing; hide `ConnectorCommand::Configs`.
2. Make the name of `connector use` optional; without one, run the same listing without touching the selection.
3. Rename the schema to `connector config list`; `connector use` has two shapes (oneOf).
4. Tests, README, AGENTS.md, release notes.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
On refactor/ti-cli-plain-files with the next ti version. `connector use` answers in two shapes, so its schema is a oneOf; the schema of the list is renamed to `connector config list` and the hidden old name has no schema entry of its own.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
ti connector config list lists the .kon files; connector configs stays hidden, connector use without a name shows the same list. Merged in PR #85 (ebdd88b).
<!-- SECTION:FINAL_SUMMARY:END -->
