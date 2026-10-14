---
id: TASK-48
title: >-
  Fuzz targets for ti-idpd and ti-directory: discovery, IDP keys, challenge,
  redirects, tokens
status: To Do
assignee: []
created_date: '2026-10-14 20:42'
labels:
  - ti-idpd
  - ti-directory
  - fuzz
dependencies: []
references:
  - rust/docs/design.md
priority: medium
ordinal: 46000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Design goal 9. The IDP-Dienst and FHIR-Directory answers are parsed before their signatures are checked.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 fuzz targets for every response parser of both crates, seeded from fixtures, and a just recipe
<!-- AC:END -->
