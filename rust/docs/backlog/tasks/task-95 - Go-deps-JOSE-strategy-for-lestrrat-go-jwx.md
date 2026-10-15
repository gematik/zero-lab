---
id: TASK-95
title: 'Go deps: JOSE strategy for lestrrat-go/jwx'
status: To Do
assignee: []
created_date: '2026-10-14 20:44'
labels:
  - go
  - deps
  - design
dependencies: []
references:
  - docs/conventions/dependencies.md
  - go/docs/design.md
priority: medium
ordinal: 93000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
jwx is the largest unaudited cryptographic dependency, has one maintainer, and is a second JOSE implementation next to brainpool/josebp.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 decided with the maintainer: go-jose, extending josebp on the standard library, or the Rust jwz through ti; plan per module
<!-- AC:END -->
