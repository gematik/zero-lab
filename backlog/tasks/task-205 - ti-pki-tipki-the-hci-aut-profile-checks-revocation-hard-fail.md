---
id: TASK-205
title: 'ti-pki, tipki: the hci-aut profile checks revocation hard-fail'
status: In Progress
assignee: []
created_date: '2026-11-03T17:42:00Z'
updated_date: '2026-11-03T17:49:00Z'
labels:
  - ti-pki
  - tipki
dependencies: []
ordinal: 212000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
hci-aut was the one profile on soft-fail, so an SMC-B whose OCSP answer could not be had was accepted. The maintainer decided it must be hard-fail like every other profile. An OCSP outage now refuses an SMC-B under this profile.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 hci-aut is hard-fail in ti-pki, tipki and the corpora
- [x] #2 A configured soft-fail does not lower it
- [x] #3 An SMC-B whose responder is unavailable is refused under hci-aut
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
The corpus changed in 4 of 6104 verdicts, all hci-aut under a configured soft-fail with the responder unavailable: 3 went from valid to invalid, and 1 stayed invalid with ocsp_unavailable in place of role_oid_missing. A configured disabled still disables.
<!-- SECTION:NOTES:END -->
