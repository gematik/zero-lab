---
id: TASK-345
title: 'epa/vau: the client checks that a response carries its request''s counter'
status: In Progress
assignee: []
created_date: '2026-11-16T18:21:00Z'
updated_date: '2026-11-16T19:48:00Z'
labels: []
dependencies: []
ordinal: 360000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Found by the ASL spike (TASK-339): A_24633 asks the client to refuse a response whose header counter is not its request's; the ASL profile on the spike branch checks it (A_26931), VAU does not.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A VAU response with another request's counter is refused, with a test named after A_24633
<!-- AC:END -->
