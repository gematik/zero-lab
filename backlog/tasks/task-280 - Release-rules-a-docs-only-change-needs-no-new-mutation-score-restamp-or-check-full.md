---
id: TASK-280
title: >-
  Release rules: a docs-only change needs no new mutation score, restamp or
  check-full
status: To Do
assignee: []
created_date: '2026-11-08T18:31:00Z'
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
- [ ] #1 the mutation gate counts only changes that can change the score: everything under the crate except README, LICENSE, docs that are not compiled into the crate (an include_str! makes them count), verification/ and fuzz/; and Cargo.toml only beyond its [package] version line; tested
- [ ] #2 stamp inputs hash a Cargo.toml without its [package] version line, in jwz-recheck and in the stamps test alike, so a version bump leaves the stamps fresh
- [ ] #3 just release skips check-full and msrv for a crate with no such change since its last tag (a docs-only release) and says so; it still runs the gate, advisories, vet and semver
- [ ] #4 rust/docs/development.md states the rules
<!-- AC:END -->
