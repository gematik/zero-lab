---
id: TASK-152
title: 'ti-cli: a smaller binary without slowing the hot paths, and a size budget'
status: To Do
assignee: []
created_date: '2026-10-28T18:29:00Z'
labels:
  - ti-cli
  - release
  - deps
milestone: m-0
dependencies: []
priority: medium
type: enhancement
ordinal: 160000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
ti is 12.4 MB on linux-musl, 11.8 MB on Windows, 9.4 MB on macOS (0.5.0). cargo bloat (macOS, 7.6 MiB .text): C code 1.4 MiB (mostly the bundled SQLite of rusqlite, ring's assembly), ti_cli 1.2 MiB, serde 1.1 MiB (the report types' Serialize code), std 0.8 MiB, rustls 0.3, clap 0.26, quick-xml 0.21, ring 0.14, roxmltree 0.03; embedded data about 0.9 MiB. ring and the two XML parsers are not where the size is (TASK-57 stays an attack-surface task). Plan: opt-level s for the tool layer (clap, serde, serde_json, ti-cli, the output code), opt-level 3 kept for crypto, parsing and verification (decision-4: performance before size); SQLite built without what the store does not use; a size budget per release target checked before a release.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Per-package opt-level in the release profile: s for the tool layer, 3 for crypto, PKI and parsing crates; sizes before and after recorded per target
- [ ] #2 SQLite compile options drop what the store does not use, with the store's tests and spec/store conformance green
- [ ] #3 A size budget for the release binaries fails the release (and a just recipe the maintainer can run) when exceeded
- [ ] #4 No measurable slowdown of pki verify, tsl verify and the store (timings before and after recorded)
<!-- AC:END -->
