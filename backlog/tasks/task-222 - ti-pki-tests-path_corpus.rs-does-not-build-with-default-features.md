---
id: TASK-222
title: 'ti-pki: tests/path_corpus.rs does not build with default features'
status: Done
assignee: []
created_date: '2026-11-05T22:03:00Z'
updated_date: '2026-11-06T06:34:00Z'
labels:
  - ti-pki
  - tests
dependencies: []
ordinal: 229000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The file is gated on brainpool (a default feature) but uses ti_pki::load::Bundle, which needs the load feature. cargo test -p ti-pki with default features fails to compile, so just test-defaults and check-full (before every release) fail. Found during TASK-50.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 the file's gate names every feature it uses, and just test-defaults passes
<!-- AC:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
tests/path_corpus.rs: bundle_001 uses ti_pki::load::Bundle, so it is gated on load; path_001 still runs with default features. just test-defaults: 904 passed. just test (all features) runs both.
<!-- SECTION:FINAL_SUMMARY:END -->
