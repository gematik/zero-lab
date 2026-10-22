---
id: TASK-135
title: >-
  Release gates fail first at release time: vet and the cross builds are outside
  just check
status: To Do
assignee: []
created_date: '2026-10-22 19:52'
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
- [ ] #1 cargo vet --locked runs in just check or check-full and in CI
- [ ] #2 A change that breaks the Linux or Windows cross build of ti-cli fails before a release
- [ ] #3 docs/development.md names where each release gate also runs
<!-- AC:END -->
