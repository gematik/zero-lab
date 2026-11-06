---
id: TASK-228
title: 'ti probe: TLS verification is turned off'
status: To Do
assignee: []
created_date: '2026-11-06T07:36:00Z'
labels:
  - ti-cli
  - security
dependencies: []
priority: medium
ordinal: 239000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Found while planning TASK-97: ti-cli/src/commands/probe.rs disables certificate verification for every probed host, production TI endpoints included. Once TASK-97 (d) exists the probe can verify with the endpoint's profile and report the verdict instead of skipping it.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 the probe verifies with the endpoint's profile and reports the TLS verdict
<!-- AC:END -->
