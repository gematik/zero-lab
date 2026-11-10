---
id: TASK-284
title: Konnektor errors name the configuration
status: To Do
assignee: []
created_date: '2026-11-10T18:40:00Z'
labels:
  - rust
  - ti-cli
dependencies: []
priority: medium
ordinal: 300000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
ti 0.6.0 test feedback: 'Konnektor: transport: io: Connection reset by peer (os error 54)' does not say which .kon failed. Maintainer: name the configuration only; the URL and the calls stay with -v.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 a Konnektor error reads 'Konnektor <name>: …'; kinds, exit codes and the hint unchanged; tested
<!-- AC:END -->
