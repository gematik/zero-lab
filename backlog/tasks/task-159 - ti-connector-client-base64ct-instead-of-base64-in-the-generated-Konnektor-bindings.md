---
id: TASK-159
title: >-
  ti-connector-client: base64ct instead of base64 in the generated Konnektor
  bindings
status: To Do
assignee: []
created_date: '2026-10-29T12:24:00Z'
labels:
  - rust
  - deps
  - connector
dependencies: []
priority: low
ordinal: 170000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
base64 0.23 is in ti-connector-client's core only for the generated Konnektor bindings, and carries unsafe (unchecked UTF-8 of its own output); base64ct, already in every core's tree, does the same. Found by the unsafe inventory of TASK-156; until then base64 is an approved exception in rust/docs/unsafe-exceptions.md.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The generated bindings and their generator use base64ct; base64 leaves ti-connector-client's normal tree
- [ ] #2 Its row leaves rust/docs/unsafe-exceptions.md and just unsafe-free passes
<!-- AC:END -->
