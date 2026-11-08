---
id: TASK-280
title: >-
  Release rules: a docs-only change needs no new mutation score, restamp or
  check-full
status: Done
assignee: []
created_date: '2026-11-08T18:31:00Z'
updated_date: '2026-11-08T18:57:00Z'
labels:
  - rust
  - release
  - testing
dependencies: []
priority: high
ordinal: 296000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
jwz 0.2.1 only fixes its README (crates.io keeps a version's README), yet the rules asked for a new mutation score (~25-40 min: the gate refused any change under the crate's directory), a full check-full (~36 min with cross builds and msrv) and a restamp (the version bump changes jwz/Cargo.toml, a browser stamp input). None of it adds assurance when no code changed. Maintainer (2026-11-08): fix the rules, then release.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 the mutation gate counts only changes that can change the score: everything under the crate except README, LICENSE, docs that are not compiled into the crate (an include_str! makes them count), verification/ and fuzz/; and Cargo.toml only beyond its [package] version line; tested
- [x] #2 just release skips check-full and msrv for a crate with no such change since its last tag (a docs-only release) and says so; it still runs the gate, advisories, vet and semver
- [x] #3 rust/docs/development.md states the rules
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Gate: scripts/mutation.py affecting <crate> <rev> lists the changed files that can change the score (everything under the crate except README, LICENSE, docs/ not compiled in by include_str!, verification/, fuzz/; Cargo.toml only beyond its [package] version line); the gate and the release use it; tested in scripts/test_mutation.py. Release: a crate with no such change and an unchanged workspace Cargo.toml and Cargo.lock since its last tag is docs-only: check-full and msrv are skipped, the gate, advisories, vet and semver run. Dropped (maintainer's goal, my call): hashing stamps' Cargo.toml without the version line. It needed jwz/tests/stamps.rs to change, which under the new gate is code and would have forced a new mutation score, and it saves only the browser restamp (~3 min): Kani and hax hash no manifest.

Found while merging: just release updated only the workspace's Cargo.lock; the fuzz workspaces' own lock files still named jwz 0.1.0. The release now updates every */fuzz/Cargo.lock offline and commits them with the bump; the three stale ones are committed.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Mutation gate counts only code (scripts/mutation.py affecting: not README, LICENSE, uncompiled docs, verification/, fuzz/, or the [package] version line); a release with no code, workspace manifest or lock change since the last tags skips check-full and msrv; releases update the fuzz workspaces' lock files. Proven on jwz 0.2.1: gate passed on the 0.2.0 score, release in minutes instead of ~36. Dropped: version-agnostic stamp hashing (would have forced a new mutation score, saves ~3 min).
<!-- SECTION:FINAL_SUMMARY:END -->
