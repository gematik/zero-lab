---
id: TASK-46
title: 'Fuzz targets for ti-pkcs12: decode with MAC, KDF and PBE parameters'
status: To Do
assignee: []
created_date: '2026-10-14 20:42'
labels:
  - ti-pkcs12
  - fuzz
dependencies: []
references:
  - docs/design/testing.md
  - rust/docs/design.md
priority: medium
ordinal: 44000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Design goal 9. ti-pkcs12 decodes identity files from outside; the iteration limits (P12-036) make fuzzing affordable.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 ti-pkcs12/fuzz with a decode target seeded from spec/pkcs12, asserting no panic, bounded time and the spec result codes, and just fuzz-ti-pkcs12
<!-- AC:END -->
