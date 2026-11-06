---
id: TASK-221
title: 'jwz: docs/guide.md example fails with default features'
status: In Progress
assignee: []
created_date: '2026-11-05T21:54:00Z'
updated_date: '2026-11-06T07:10:00Z'
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
- [x] #1 the example holds under every feature set jwz's docs are tested with, and that set includes the defaults
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Rewrite the guide example so it holds under every feature set (interop accepts every algorithm the registry implements, strict does not); just test also runs cargo test -p jwz --doc with default features.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
3582e270: the example asserts A128KW (interop has it, strict not), true under every feature set; just test and check-jwz run cargo test -p jwz --doc with defaults; the old example fails there at guide line 75, the new one passes.
<!-- SECTION:NOTES:END -->
