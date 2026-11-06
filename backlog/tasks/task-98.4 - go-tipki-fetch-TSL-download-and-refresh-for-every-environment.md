---
id: TASK-98.4
title: 'go/tipki/fetch: TSL download and refresh for every environment'
status: To Do
assignee: []
created_date: '2026-11-06T14:01:00Z'
labels:
  - go
  - security
dependencies: []
parent_task_id: TASK-98
ordinal: 247000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
idpd's FetchingTrust (decision-12) moved into go/tipki/fetch, environments prod, ref, test and dev, used by idpd and by epa as the source of the ti snapshot.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 idpd uses go/tipki/fetch with its tests unchanged in substance
- [ ] #2 the fetcher serves the snapshot titls swaps
<!-- AC:END -->
