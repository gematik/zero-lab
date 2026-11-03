---
id: TASK-58
title: 'Dependencies: jiff and arc-swap'
status: Done
assignee: []
created_date: 2026-10-14 20:43
updated_date: '2026-11-01T14:09:00Z'
labels:
  - ti-cli
  - ti-pki
  - deps
milestone: m-0
dependencies: []
references:
  - docs/conventions/dependencies.md
  - rust/docs/design.md
priority: medium
ordinal: 56000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
jiff only renders local time in CLI output; arc-swap has one use in ti-pki's reloader.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 jiff dropped (UTC output) or kept with a recorded reason; arc-swap replaced by a std lock or kept with measurements (performance before size)
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
arc-swap replaced by std::sync::RwLock. Measured with a writer swapping every millisecond, far above a real reload: 1 reader 12.3 vs 13.7 ns, 4 readers 176 vs 420 ns, 16 readers 1,353 vs 4,209 ns per read (arc-swap vs RwLock). Slower under contention, but microseconds at worst per snapshot, and the only caller in the repository is ti-cli. It removes a crate with unsafe from a core. jiff kept: ti-cli only (a host), jiff-core alone on macOS and musl, plus jiff-tzdb and windows-link on Windows; std has no time zones, and UTC is not what a user compares with.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
arc-swap is gone from ti-pki, its unsafe exception and vet exemption too; the reloader uses a std RwLock. jiff stays in ti-cli for local time, with the reason next to it. just check green.
<!-- SECTION:FINAL_SUMMARY:END -->
