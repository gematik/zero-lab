---
id: TASK-64
title: One HTTP vocabulary for the Transport traits (ti-http)
status: To Do
assignee: []
created_date: '2026-10-14 20:43'
labels:
  - design
  - ti-pki
  - ti-idpd
  - ti-connector-client
dependencies: []
references:
  - rust/docs/design.md
priority: medium
ordinal: 62000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
ti-pki, ti-idpd and ti-connector-client each define their own Transport trait, so a host writes three adapters (Sans I/O and pluggable transports, Open).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 decided before any of the three crates reaches 1.0: a small ti-http crate of plain data types and one async trait, or the reason to keep three
<!-- AC:END -->
