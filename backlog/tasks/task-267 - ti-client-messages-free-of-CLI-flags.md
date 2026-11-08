---
id: TASK-267
title: 'ti-client: messages free of CLI flags'
status: To Do
assignee: []
created_date: '2026-11-08T06:34:00Z'
labels:
  - rust
dependencies: []
ordinal: 283000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Two ti-client messages name CLI flags (--validation-profile, --offline) and stayed so the ti CLI's JSON did not change. The Tauri app needs its own wording: ti-client reports a typed reason, each front end words it. Found during TASK-250.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 no ti-client message names a CLI flag; the ti CLI's output is unchanged
<!-- AC:END -->
