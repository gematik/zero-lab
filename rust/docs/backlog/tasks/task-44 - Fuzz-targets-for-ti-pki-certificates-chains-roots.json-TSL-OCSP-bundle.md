---
id: TASK-44
title: 'Fuzz targets for ti-pki: certificates, chains, roots.json, TSL, OCSP, bundle'
status: To Do
assignee: []
created_date: '2026-10-14 20:42'
labels:
  - ti-pki
  - fuzz
dependencies: []
references:
  - rust/docs/design.md
priority: medium
ordinal: 42000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Design goal 9: every reader of attacker-chosen bytes has a fuzz target. ti-pki parses certificates, roots.json, the TSL (quick-xml) and OCSP responses from outside before any signature is checked, and the offline bundle. Layout as jwz/fuzz (Fuzzing section of rust/docs/design.md).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 a fuzz crate ti-pki/fuzz with one target per entry point, committed seeds from spec corpora and real TI artefacts, invariants beyond no-panic, and just fuzz-ti-pki
<!-- AC:END -->
