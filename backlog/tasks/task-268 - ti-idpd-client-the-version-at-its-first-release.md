---
id: TASK-268
title: 'ti-idpd-client: the version at its first release'
status: Done
assignee: []
created_date: '2026-11-08T06:34:00Z'
updated_date: '2026-11-17T08:21:00Z'
labels:
  - rust
  - release
dependencies: []
ordinal: 284000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
ti-idpd was published as 0.1.0; TASK-246 renamed it to ti-idpd-client. Decide at its first release whether it starts at 0.1.0 under the new name and what happens to the old crate on crates.io (a final release pointing to the new name, or yank).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 the first release of ti-idpd-client follows a recorded decision
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Decision (maintainer, 2026-11-08): ti-idpd-client's first release is 0.2.0, following ti-idpd 0.1.0. just release ti-idpd-client=0.2.0 sets it at the release.

Decision (maintainer, 2026-11-17): ti-idpd-client starts at 0.2.0, above the old git tag rust/ti-idpd/v0.1.0, so the two names never share a version. Neither ti-idpd nor ti-idpd-client is on crates.io (the workspace has publish = false), so there is no old crate to yank or redirect; the old tag stays as history. The version is set at the first release, as the release steps say (no version edits while developing).
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
ti-idpd-client released as 0.2.0 (rust/ti-idpd-client/v0.2.0, 2026-11-17), above the old git tag rust/ti-idpd/v0.1.0, as the maintainer decided. Gates: check-full, mutation gate (93.3%, threshold 0.8), advisories, vet, msrv, semver, jwz-recheck. The fuzz lock files were brought to rsa 0.10.0 first (35d450f9).
<!-- SECTION:FINAL_SUMMARY:END -->
