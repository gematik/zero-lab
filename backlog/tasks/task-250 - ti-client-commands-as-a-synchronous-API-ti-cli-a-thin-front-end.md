---
id: TASK-250
title: 'ti-client: commands as a synchronous API, ti-cli a thin front end'
status: To Do
assignee: []
created_date: '2026-11-07T15:53:00Z'
updated_date: '2026-11-07T16:03:00Z'
labels:
  - ti-client
  - ti-cli
  - architecture
dependencies:
  - TASK-249
  - TASK-248
  - TASK-246
references:
  - docs/architecture.md
priority: medium
type: task
ordinal: 266000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Decision-15: the command-line tool and the Tauri app run the same operations, so the operations live in ti-client and return the engines' model types; ti-cli only parses arguments, reads its configuration and prints. A desktop app depending on ti-cli would pull in clap and terminal output.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 each ti command's operation is a function of ti-client returning an engine's model type or a typed result; ti-cli calls it and prints
- [ ] #2 ti-cli's output, exit codes and schemas are unchanged
- [ ] #3 ti-client does not depend on clap or on terminal output
<!-- AC:END -->
