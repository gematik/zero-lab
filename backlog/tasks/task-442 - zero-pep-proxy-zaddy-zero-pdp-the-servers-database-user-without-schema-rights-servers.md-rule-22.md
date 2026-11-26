---
id: TASK-442
title: >-
  zero-pep-proxy, zaddy, zero-pdp: the server's database user without schema
  rights (servers.md rule 22)
status: Done
assignee: []
created_date: '2026-11-26T19:06:00Z'
updated_date: '2026-11-26T23:17:00Z'
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
- [x] #1 zero-pep-proxy and zaddy open the store without WithMigrate by default and start with a user that has no schema rights, shown by a test
- [x] #2 The schema steps can be applied before a rollout without a server doing it, and the e2e guide and the chart show how
- [x] #3 Applying the steps at start is a setting that is off unless set, logged when on
- [x] #4 zero-pdp is decided and the decision recorded
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
2026-11-26: zaddy keeps no database any more (maintainer; its revocations are TASK-443), so this task is about zero-pep-proxy and zero-pdp alone.

2026-11-26, on feat/kv-db-tls. zero-pep-proxy: Open without WithMigrate by default; PEP_DATABASE_MIGRATE=true (one exact value) lets it apply expand steps at start, logged as a warning; zero-pep-proxy migrate [contract] applies the steps and stops, a subcommand of the existing host with the same database variables and a URL whose user may change the schema (a small command in an existing host; the maintainer's rule 'hosts are built elsewhere' is about new hosts, my reading). Tests: the setting read as an agreement; the subcommand refuses unknown words and a missing URL; against Postgres (PEP_PG_DSN): on a fresh database the server refuses with schema.ErrVersion, after migrate it opens as a role with DML rights only and writes, migrate run twice is fine. CONFIG.md, DOCKERHUB.md, .env.example and the e2e README (PEP_DATABASE_MIGRATE=true for the local stack) follow; no chart lives here, zero-lab-k8s needs the Job or the setting (other repository). zaddy keeps no database since today. zero-pdp: keeps WithMigrate, recorded in the code and the release notes as the exception of a frozen host; my decision under the freeze, not the maintainer's.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
zero-pep-proxy no longer changes its store's schema by default: zero-pep-proxy migrate applies the steps as a job before a rollout with a user that may, PEP_DATABASE_MIGRATE=true lets the server do it, and without either it refuses a database that lacks a step. Tested against Postgres with a server user that may only read and write rows. zaddy keeps no database (TASK-443 for its revocations); zero-pdp keeps applying its schema as a recorded exception of a frozen host. Released with go/kv/postgres v0.14.0.
<!-- SECTION:FINAL_SUMMARY:END -->
