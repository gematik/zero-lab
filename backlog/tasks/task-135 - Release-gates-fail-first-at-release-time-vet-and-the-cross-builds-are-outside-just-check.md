---
id: TASK-135
title: >-
  Release gates fail first at release time: vet and the cross builds are outside
  just check
status: Done
assignee: []
created_date: 2026-10-22 19:52
updated_date: '2026-10-26T12:49:00Z'
labels:
  - rust
  - release
  - ci
dependencies: []
priority: high
ordinal: 146000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The ti-cli 0.5.0 release failed twice on checks that just check never runs: cargo vet (rustls-webpki 0.103.16 and webpki-root-certs 1.0.10 had no exemption, though the bump landed in 58bba18), and the cross builds of cli-targets (ti-cli's include_str! of ../spec/store/schema.sql, from TASK-103.4, could not be read in the container until 2026-10-22). Both broke on main long before the release. Move them in front of the release: cargo vet --locked into just check (or check-full), and a cross build of ti-cli for linux-musl and windows-gnu on changes to ti-cli or its dependencies (CI or check-full), with Windows warnings denied once TASK-134 is done.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 cargo vet --locked runs in just check or check-full and in CI
- [x] #2 A change that breaks the Linux or Windows cross build of ti-cli fails before a release
- [x] #3 docs/development.md names where each release gate also runs
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
There is no CI in the repository (no .github), so 'in CI' of AC 1 maps to the just tiers: vet joins check (0.4 s with --locked); cli-targets gets mode=check, clippy -D warnings of ti-cli in the same cross containers and mounts as the release build, run by cli-check in check-full (Docker needed, as for releases). docs/development.md says where each release gate also runs. First run found clippy 1.99 lints (TASK-147: the container's stable was ahead of the host's 1.98.1) and the Windows warnings (TASK-134).
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
vet runs in just check; cli-check (cli-targets mode=check: clippy -D warnings of ti-cli in the release cross containers) runs in check-full; docs/development.md says where each release gate also runs. No CI exists, so the just tiers stand in for it (notes). Verified: just check green with vet, just cli-check green for musl and windows-gnu after it had caught TASK-147 and TASK-134.
<!-- SECTION:FINAL_SUMMARY:END -->
