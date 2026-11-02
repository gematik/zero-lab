---
id: TASK-157
title: 'ti-cli: connector config migrate (.kon to the new rules)'
status: To Do
assignee: []
created_date: '2026-10-29T11:06:00Z'
labels:
  - ti-cli
  - connector
  - security
  - parked
dependencies:
  - TASK-104
references:
  - >-
    backlog/decisions/decision-7 -
    Tokens-persisted-only-as-sealed-records-under-a-profile-keyring.md
priority: medium
ordinal: 168000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Bring existing .kon files to the rules of TASK-136 (formerly TASK-136.3). Where secrets go depends on the planned secret management (TASK-104, decision-7); until then the .kon itself is the secret.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 config migrate NAME sets mode 0600 on the file and 0700 on its directory and reports what it changed
- [ ] #2 Moving inline secrets out of the .kon follows the secret-management decision made by then; until it exists, migrate only reports them
- [ ] #3 A backup of the original is kept with mode 0600 until the migrated file passed config test
- [ ] #4 Tests named after the requirement each proves
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
2026-10-29 zurückgestellt (Maintainer): wartet auf das Secret-Management (TASK-104 Plattform-Keyring, decision-7). Erst danach steht fest, wohin migrate die Geheimnisse einer .kon verschiebt. Aus TASK-136.3 herausgelöst, damit TASK-136 geschlossen werden kann.
<!-- SECTION:NOTES:END -->
