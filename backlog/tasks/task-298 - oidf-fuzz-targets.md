---
id: TASK-298
title: 'oidf: fuzz targets'
status: In Progress
assignee: []
created_date: '2026-11-12T21:08:00Z'
updated_date: '2026-11-14T20:52:00Z'
labels: []
dependencies: []
ordinal: 314000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
go/oidf has no fuzz target, though it parses entity statements, the IDP list, signed JWKS and encrypted ID tokens from the network (principle 9). Found by zeta-pdp-go, which needs it for the login of insured persons at a sektoral IDP (its TASK-54) or as named.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Fuzz targets for each parser of the module, run by the module's check
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
2026-11-14: done as part of TASK-315 on feat/oidf-rp: a fuzz target for each parser the module has after it.
<!-- SECTION:NOTES:END -->
