---
id: TASK-45
title: 'Fuzz targets for ti-xmldsig: XML parsing, C14N, signature verification'
status: To Do
assignee: []
created_date: '2026-10-14 20:42'
labels:
  - ti-xmldsig
  - fuzz
dependencies: []
references:
  - rust/docs/design.md
priority: medium
ordinal: 43000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Design goal 9. ti-xmldsig parses and canonicalises the TSL before its signature is verified.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 ti-xmldsig/fuzz with targets for parsing, C14N (canonical form is a fixed point) and verification of a TSL-shaped document, seeded from spec/tsl-xmldsig, and just fuzz-ti-xmldsig
<!-- AC:END -->
