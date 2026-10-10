---
id: TASK-21
title: 'jwz: aws-lc backend'
status: To Do
assignee: []
created_date: '2026-10-10 05:58'
labels:
  - jwz
dependencies: []
priority: low
ordinal: 21000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
A FIPS path: a crate implementing jwz::crypto over aws-lc-rs, outside jwz's tree (ADR 0001, key point 1).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Same backend test suite as RustCrypto (Wycheproof through the backend traits)
- [ ] #2 jwz-backends still passes for the jwz crates
<!-- AC:END -->
