---
id: TASK-387
title: 'kv: Reseal marks a record of before the marks that the current key sealed'
status: Done
assignee: []
created_date: '2026-11-18 21:35'
updated_date: '2026-11-18 21:35'
labels: []
dependencies: []
ordinal: 396000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Found before the first use on an existing database (zeta-pdp-go, directory-ref): a row written by a version without marks counts among the others (Resealer.Others), as it should, but Reseal left it alone when the current key had sealed it, so it was never marked and was found again in every walk; a store that came from a version without marks never ran out of others. Reseal now writes such a record again, which gives it its mark.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 A record without a mark that the current key sealed is written again by Reseal once, and then is not among the others
<!-- AC:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
go/kv/sealed.go: Reseal asks the marker below whether the record is among the others when the current key sealed it, and writes it again if so. Test on Postgres with a row written through a store without marks. just check-changed passed.
<!-- SECTION:FINAL_SUMMARY:END -->
