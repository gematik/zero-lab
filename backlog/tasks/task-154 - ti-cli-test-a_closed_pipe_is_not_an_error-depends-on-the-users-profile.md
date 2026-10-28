---
id: TASK-154
title: ti-cli test a_closed_pipe_is_not_an_error depends on the user's profile
status: To Do
assignee: []
created_date: '2026-10-28T18:44:00Z'
labels:
  - ti-cli
  - test
milestone: m-0
dependencies: []
priority: medium
type: bug
ordinal: 162000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The test runs ti pki inspect without the tests' environment, so it reads the user's default profile: with a stale TSL in that cache, inspect warns on stderr (no keyring, TSL not kept) and the test, which expects an empty stderr, fails. Run it in the tests' environment (no user profile, cache or state) like every other test.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The test runs ti in the tests' environment and passes whatever the user's profile holds
<!-- AC:END -->
