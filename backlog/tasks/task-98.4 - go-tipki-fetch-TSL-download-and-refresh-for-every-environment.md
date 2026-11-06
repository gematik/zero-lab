---
id: TASK-98.4
title: 'go/tipki/fetch: TSL download and refresh for every environment'
status: In Progress
assignee: []
created_date: '2026-11-06T14:01:00Z'
updated_date: '2026-11-06T16:48:00Z'
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
- [x] #1 idpd uses go/tipki/fetch with its tests unchanged in substance
- [x] #2 the fetcher serves the snapshot titls swaps
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
On spec/go-pki-validation (6f37765d, 791781db): go/tipki/fetch (Environment prod/ref/test/dev, dev on ref's hosts; New, Current, Source, Close). Source() is a titls.TrustSource: swapped after a refresh that changed the store, withdrawn (nil) at the instant the copy stops standing (MaxBundleAge or NextUpdate), not swapped for an unchanged one. idpd.FetchingTrust wraps it; fetching tests moved to tipki/fetch with their IDPV-007/008 names. go mod tidy -diff in idpd fails until tipki is tagged/synced (in-repo pin v0.31.1 lacks fetch).
<!-- SECTION:NOTES:END -->
