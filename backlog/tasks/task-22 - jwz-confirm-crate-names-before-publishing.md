---
id: TASK-22
title: 'jwz: confirm crate names before publishing'
status: To Do
assignee: []
created_date: 2026-10-10 05:58
updated_date: '2026-11-06T07:11:00Z'
labels:
  - jwz
  - decision
dependencies: []
priority: medium
ordinal: 13000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
jwz, jwz-brainpool and ti-jwz are publish = false until the crate names are confirmed with the maintainers (ADR 0001; the licence is EUPL-1.2, gematik GmbH, as for the workspace). The names are free on crates.io as of milestone 1.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Crate names confirmed and recorded (ADR 0001)
- [ ] #2 Publishing enabled in Cargo.toml and release-plz.toml once the registry decision is made
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Maintainer, 2026-11-06: jwz-brainpool goes into ti-jwz (TASK-225), so the names are jwz and ti-jwz; publish stays off. Record the confirmed names, remove jwz-brainpool from release-plz.toml.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Maintainer, 2026-11-06: names jwz and ti-jwz (jwz-brainpool merged into ti-jwz, TASK-225); publish stays off. Recorded in ADR 0001 (9a2e2d93). The tags rust/<crate>/vX.Y.Z are already in release-plz.toml. AC 2 waits on the registry decision.
<!-- SECTION:NOTES:END -->
