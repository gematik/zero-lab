---
id: TASK-442
title: >-
  zero-pep-proxy, zaddy, zero-pdp: the server's database user without schema
  rights (servers.md rule 22)
status: To Do
assignee: []
created_date: '2026-11-26T19:06:00Z'
updated_date: '2026-11-26T19:56:00Z'
labels:
  - go
  - security
dependencies: []
priority: medium
ordinal: 451000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
servers.md rule 22 since TASK-428: a server does not change its schema; its database role reads and writes rows, and a migration job with credentials of its own applies the schema steps before a rollout. The three hosts of this repository pass postgres.WithMigrate() to Open and so apply the steps themselves, with a user that may create and alter tables: kept on 2026-11-25 so that nothing changed for them. To decide for each: zero-pep-proxy and zaddy get the setting the rule allows (apply the steps itself, off unless set) and a way to run Migrate as a job (a subcommand of the same image with the admin credentials from files, or the deployment's own job); zaddy only reads revocations and needs no schema rights at all once it does not migrate; zero-pdp is frozen and either keeps WithMigrate, recorded as an exception, or goes. The charts in zero-lab-k8s and the compose files of the e2e guide follow.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 zero-pep-proxy and zaddy open the store without WithMigrate by default and start with a user that has no schema rights, shown by a test
- [ ] #2 The schema steps can be applied before a rollout without a server doing it, and the e2e guide and the chart show how
- [ ] #3 Applying the steps at start is a setting that is off unless set, logged when on
- [ ] #4 zero-pdp is decided and the decision recorded
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
2026-11-26: zaddy keeps no database any more (maintainer; its revocations are TASK-443), so this task is about zero-pep-proxy and zero-pdp alone.
<!-- SECTION:NOTES:END -->
