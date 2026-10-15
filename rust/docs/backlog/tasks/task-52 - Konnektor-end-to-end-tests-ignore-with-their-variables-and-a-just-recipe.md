---
id: TASK-52
title: 'Konnektor end-to-end tests: #[ignore] with their variables and a just recipe'
status: To Do
assignee: []
created_date: '2026-10-14 20:42'
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
- [ ] #1 the tests are #[ignore = "needs TI_TEST_KON_PATH: just ..."], fail when run without the variable, and a just recipe runs them; the Gated tests table in rust/docs/development.md points to it
<!-- AC:END -->
