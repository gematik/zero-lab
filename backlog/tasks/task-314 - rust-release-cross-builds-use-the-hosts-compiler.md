---
id: TASK-314
title: 'rust release: cross builds use the host''s compiler'
status: In Progress
assignee: []
created_date: '2026-11-14T18:26:00Z'
updated_date: '2026-11-15T09:10:00Z'
labels: []
dependencies: []
ordinal: 329000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
just cli-targets runs 'rustup toolchain add stable-x86_64-unknown-linux-gnu', which moves the toolchain cross builds the Linux and Windows binaries with to the newest stable, while the host builds the macOS binary with its own stable. On 2026-11-14 that pulled in the stable of 2026-11-12, whose x86_64-pc-windows-gnu std links -lsynchronization; cross 0.2.5's Windows image has a MinGW without that library, so the release failed at linking ti.exe. ti 0.6.2 was released with RUSTUP_TOOLCHAIN=1.99.1 (the host's compiler, that toolchain given the same components and targets as stable). Fix the recipe so that every target of a release is built by the host's compiler version (derive it from rustc --version and use that version's linux-gnu toolchain for cross), and decide when to move to a Windows image whose MinGW has libsynchronization, before the host's stable reaches that release.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 cli-targets builds every target with the host's rustc version, and a mismatch cannot happen silently
- [ ] #2 The Windows target links with the current stable, through a newer cross image or a documented pin
- [ ] #3 The development guide's release steps say which compiler the binaries are built with
<!-- AC:END -->
