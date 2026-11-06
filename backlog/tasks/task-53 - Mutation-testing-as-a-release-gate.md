---
id: TASK-53
title: Mutation testing as a release gate
status: Done
assignee: []
created_date: 2026-10-14 20:43
updated_date: '2026-11-06T06:18:00Z'
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

Maintainer confirmed the 0.8 thresholds on 2026-11-06.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Release gate for mutation testing: rust/mutation-scores.toml holds a score per crate (just mutants-record) and a threshold of 0.8 for the security crates jwz, jwz-brainpool, ti-connector-client, ti-idpd, ti-jwz, ti-pkcs12 and ti-pki, confirmed by the maintainer; just release runs just mutants-gate after check-full and refuses a crate whose score is missing, stale or under its threshold. ti-pkcs12 (79.2%) waits on TASK-218.
<!-- SECTION:FINAL_SUMMARY:END -->
