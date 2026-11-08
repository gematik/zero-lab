---
id: TASK-278
title: 'jwz: same_media_type strips application/ only from a bare subtype'
status: To Do
assignee: []
created_date: '2026-11-08T15:20:00Z'
updated_date: '2026-11-08T15:26:00Z'
labels:
  - jwz
milestone: m-1
dependencies: []
priority: low
ordinal: 294000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Found by TASK-258. RFC 7515 §4.1.9 lets typ omit the application/ prefix only when no other / is present; same_media_type drops application/ even when another / follows, so application/a/b equals a/b.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 the prefix is stripped only when no other / remains, with a test case named after RFC 7515 §4.1.9
<!-- AC:END -->
