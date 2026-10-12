---
id: TASK-34
title: >-
  Release: ti-cli 0.4.0, ti-idpd 0.2.0, ti-directory 0.1.0, ti-pki and friends
  (the big release)
status: Done
assignee: []
created_date: '2026-10-11 11:48'
updated_date: '2026-10-11 14:14'
labels:
  - release
  - ti-cli
dependencies:
  - TASK-33
priority: high
ordinal: 2000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Everything since ti-cli 0.3.0 sits under Unreleased: directory login, IDP certificates against the TSL, OCSP cache, CA bundle subsets, --nist-only as a filter, gemSpec naming (decision-5, breaking profile names), and TASK-33's login restructure. The 0.4.0 prep on 2026-10-11 was undone to wait for this one release. just release only knows ti-cli and its just audit step fails rebuilding the semver baseline from the 0.2.0 tag (rsa 0.10.0-rc.18 compile error, see TASK-12), so 0.3.0 was cut by hand (cli-targets, SHA256SUMS, just publish). Fix the recipe for a multi-crate release (versions and ReleaseNotes sections for every crate with Unreleased entries, tags per crate) and a working or skippable semver step, then release and update the brew tap.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 just release (or a successor) bumps, moves ReleaseNotes sections and tags every crate with unreleased changes in one run; the semver step passes or is explicitly skipped with a reason
- [x] #2 ti 0.4.0 on GitHub releases (darwin arm64, linux musl, windows) and in the brew tap; ti version shows 0.4.0
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Tooling done on feat/directory-login-release (2026-10-11): just release takes crate=version pairs (bumps, workspace requirements, ReleaseNotes sections, Cargo.lock, jwz-recheck, ti binaries when ti-cli is in it, one commit, a tag per crate; refuses a crate with more than one Unreleased block); just publish pushes every crate tag of the release commit; the semver step skips ti-cli (binary; semver-checks rebuilds without Cargo.lock and picks a pkcs1 rc the pinned rsa rc does not fit) and confirms ti-idpd needs 0.2.0 (3 breaking changes). The two ti-cli blocks under Unreleased were merged. The release itself runs from main after the merge.

Released 2026-10-11: ti-cli 0.4.0 only (user's choice); ti-idpd (needs 0.2.0) and ti-directory keep their notes under Unreleased. GitHub release rust/ti-cli/v0.4.0 with darwin arm64, linux musl, windows binaries and SHA256SUMS; brew formula spilikin/tap/ti at 0.4.0. Before it, cargo vet needed exemptions for the proptest 1.12 test dependencies, and the gate now checks semver only for the released crates after their bumps (a337eb1).
<!-- SECTION:NOTES:END -->
