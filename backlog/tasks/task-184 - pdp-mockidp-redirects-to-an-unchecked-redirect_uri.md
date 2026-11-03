---
id: TASK-184
title: 'pdp: mockidp redirects to an unchecked redirect_uri'
status: Done
assignee: []
created_date: '2026-11-02T15:42:00Z'
updated_date: '2026-11-02T23:09:00Z'
labels:
  - go
  - security
dependencies: []
priority: low
ordinal: 194000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
authzserver/mockidp/mockidp.go redirects to redirect_uri from the form with no check. It only compiles with -tags mockidp, so the exposure depends on that tag never shipping. Found by gosec G710 under the tag (TASK-86).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 The mock checks redirect_uri, or a release check proves the tag never ships, and the nolint line naming this task is gone
<!-- AC:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Fixed with requirement-named tests in the consolidation.
<!-- SECTION:FINAL_SUMMARY:END -->
