---
id: TASK-22
title: 'jwz: confirm crate names before publishing'
status: Done
assignee: []
created_date: 2026-10-10 05:58
updated_date: '2026-11-07T08:47:00Z'
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
- [x] #2 Publishing enabled in Cargo.toml and release-plz.toml once the registry decision is made
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Maintainer, 2026-11-06: jwz-brainpool goes into ti-jwz (TASK-225), so the names are jwz and ti-jwz; publish stays off. Record the confirmed names, remove jwz-brainpool from release-plz.toml.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Maintainer, 2026-11-06: names jwz and ti-jwz (jwz-brainpool merged into ti-jwz, TASK-225); publish stays off. Recorded in ADR 0001 (9a2e2d93). The tags rust/<crate>/vX.Y.Z are already in release-plz.toml. AC 2 waits on the registry decision.

2026-11-06: maintainer: publish jwz to crates.io now (ti-jwz later); org team owner (github:gematik:<team>) added next week. Steps: publish enabled for jwz only, mutation score, just release jwz=0.1.0, cargo publish -p jwz, push main and tag.

2026-11-06: jwz 0.1.0 published to crates.io (release 86c91895, tag rust/jwz/v0.1.0, mutation score 0.885), first publish by the maintainer's account. Open: add the gematik GitHub team as owner (cargo owner --add github:gematik:<team> jwz) once a gematik org owner approved crates.io's OAuth access; ti-jwz not published yet.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
jwz 0.1.0 is published on crates.io (release 86c91895, tag rust/jwz/v0.1.0, mutation score 0.885). Publishing is enabled for jwz only, in Cargo.toml (publish = ["crates-io"], include list) and release-plz.toml. ti-jwz stays unpublished. The gematik team as crates.io owner moves to TASK-239.
<!-- SECTION:FINAL_SUMMARY:END -->
