---
id: TASK-136.3
title: 'Konnektor configuration: config migrate'
status: To Do
assignee: []
created_date: '2026-10-29T06:44:00Z'
updated_date: '2026-10-29T06:48:00Z'
labels:
  - ti-cli
  - connector
  - security
milestone: m-0
dependencies: []
parent_task_id: TASK-136
priority: medium
ordinal: 167000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Third part of TASK-136: bring existing .kon files to the new rules. Where secrets go depends on the planned secret management (TASK-104, decision-7); until then the .kon itself is the secret.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 config migrate NAME sets mode 0600 on the file and 0700 on its directory and reports what it changed
- [ ] #2 Moving inline secrets out of the .kon follows the secret-management decision made by then; until it exists, migrate only reports them
- [ ] #3 A backup of the original is kept with mode 0600 until the migrated file passed config test
- [ ] #4 Tests named after the requirement each proves
<!-- AC:END -->
