---
id: TASK-49
title: 'Fuzz targets for ti-report: TSL view and certificate description'
status: To Do
assignee: []
created_date: '2026-10-14 20:42'
labels:
  - ti-report
  - wasm
  - fuzz
dependencies: []
references:
  - docs/design/testing.md
  - rust/docs/design.md
priority: medium
ordinal: 47000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Design goal 9. ti-report is what ti-wasm hands hostile bytes to in the browser.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 fuzz targets for verify_tsl and describe_certificate inputs, seeded from the TSL fixtures, and a just recipe
<!-- AC:END -->
