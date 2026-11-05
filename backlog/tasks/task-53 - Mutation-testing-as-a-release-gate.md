---
id: TASK-53
title: Mutation testing as a release gate
status: In Progress
assignee: []
created_date: 2026-10-14 20:43
updated_date: '2026-11-05T22:12:00Z'
labels:
  - tests
  - release
dependencies: []
references:
  - docs/design/testing.md
  - rust/docs/design.md
priority: medium
ordinal: 51000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
cargo-mutants runs by hand (just mutants). A mutation score per crate before a release would make it a gate (docs/design/testing.md, Verification and tooling).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 a mutation score per crate recorded before release, a threshold for the security crates, and the release procedure checks it
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
On test/coverage-and-mutation-gate (4294d8f9): mutation-scores.toml, just mutants-record / mutants-gate, gate in just release after check-full; score (caught+timeout)/(caught+missed+timeout); thresholds 0.8 proposed for jwz, jwz-brainpool, ti-jwz, ti-pki, ti-pkcs12, ti-idpd, ti-connector-client (maintainer to confirm). Calibration: ti-types 92.0% (3 min), ti-pkcs12 79.2% (10 min, default features) -> ti-pkcs12 task for its 37 survivors. No score recorded yet: each is measured by the recipe before a release.

Merged into main at 50ea3d15; stays In Progress until the maintainer confirms the 0.8 thresholds.
<!-- SECTION:NOTES:END -->
