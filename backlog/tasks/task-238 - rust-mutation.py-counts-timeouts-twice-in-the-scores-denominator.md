---
id: TASK-238
title: 'rust: mutation.py counts timeouts twice in the score''s denominator'
status: In Progress
assignee: []
created_date: '2026-11-06T19:41:00Z'
updated_date: '2026-11-07T16:07:00Z'
labels:
  - rust
  - testing
dependencies: []
priority: low
ordinal: 254000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Found while recording jwz's score (TASK-22): record() computes killed = caught + timeout and counted = killed + missed + timeout, so a timeout counts twice in the denominator; the docstring and testing rules say (caught + timeout) / (caught + missed + timeout). The error only lowers scores, so the gate never passes a crate it should refuse; recorded scores of crates with timeouts are too low.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 the recorded score is (caught + timeout) / (caught + missed + timeout), with a test
<!-- AC:END -->
