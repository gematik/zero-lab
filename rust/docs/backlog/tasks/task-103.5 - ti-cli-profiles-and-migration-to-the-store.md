---
id: TASK-103.5
title: 'ti-cli: profiles and migration to the store'
status: To Do
assignee: []
created_date: '2026-10-15 17:45'
labels:
  - ti-cli
dependencies:
  - TASK-103.4
parent_task_id: TASK-103
priority: medium
ordinal: 106000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
--profile, TI_PROFILE, active file; ti profile list|use|create|delete|show; FileCacheStore replaced by a CacheStore adapter over cache.db; TSL rollback state and comfort store moved into state.db (comfort sealed); old state imported once.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 profiles resolve as STORE-7xx
- [ ] #2 ti cache clear empties the profile's cache.db
- [ ] #3 TslStateFile and ComfortStore removed; their data migrated
<!-- AC:END -->
