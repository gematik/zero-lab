---
id: TASK-47
title: >-
  Fuzz targets for ti-connector-client: .kon files, SOAP responses and faults,
  service directory
status: To Do
assignee: []
created_date: '2026-10-14 20:42'
labels:
  - ti-connector-client
  - fuzz
dependencies: []
references:
  - rust/docs/design.md
priority: medium
ordinal: 45000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Design goal 9. A Konnektor's answers and the .kon file are input from outside.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 ti-connector-client/fuzz with targets for Dotkon::parse, the SOAP decoding and the service directory, seeded from the recorded runs, and a just recipe
<!-- AC:END -->
