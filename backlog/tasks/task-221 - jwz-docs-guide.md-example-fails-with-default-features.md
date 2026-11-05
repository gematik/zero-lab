---
id: TASK-221
title: 'jwz: docs/guide.md example fails with default features'
status: To Do
assignee: []
created_date: '2026-11-05T21:54:00Z'
labels:
  - jwz
  - tests
dependencies: []
ordinal: 228000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The example at docs/guide.md line 75 asserts the interop profile has more signature algorithms than strict, which holds only with the hmac feature. just check tests jwz's doc examples with hmac on, so the default-feature run that fails is not checked anywhere.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 the example holds under every feature set jwz's docs are tested with, and that set includes the defaults
<!-- AC:END -->
