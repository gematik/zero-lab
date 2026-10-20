---
id: TASK-52
title: 'Konnektor end-to-end tests: #[ignore] with their variables and a just recipe'
status: Done
assignee: []
created_date: '2026-10-14 20:42'
updated_date: '2026-10-20 17:47'
labels:
  - ti-connector-client
  - tests
dependencies: []
references:
  - docs/design/testing.md
priority: medium
ordinal: 50000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
ti-connector-client/tests/e2e.rs returns early when TI_TEST_KON_PATH is unset, so the tests show as passed. docs/design/testing.md, Env-gated tests run before every release.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 the tests are #[ignore = "needs TI_TEST_KON_PATH: just ..."], fail when run without the variable, and a just recipe runs them; the Gated tests table in rust/docs/development.md points to it
<!-- AC:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
The two tests in ti-connector-client/tests/e2e.rs are #[ignore] with their recipe in the reason and fail without TI_TEST_KON_PATH (and TI_TEST_KON_INTERACTIVE=1 for the PIN test) instead of passing; just konnektor-e2e and just konnektor-e2e-interactive run them; the gated-tests table in rust/docs/development.md and the crate README point to them.
<!-- SECTION:FINAL_SUMMARY:END -->
