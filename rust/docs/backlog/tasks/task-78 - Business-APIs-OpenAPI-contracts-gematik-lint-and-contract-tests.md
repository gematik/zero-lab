---
id: TASK-78
title: 'Business APIs: OpenAPI contracts, gematik lint and contract tests'
status: To Do
assignee: []
created_date: '2026-10-14 20:44'
labels:
  - go
  - api
dependencies: []
references:
  - docs/design/servers.md
  - go/docs/design.md
priority: medium
ordinal: 76000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
There are no OpenAPI contracts in the repository, so just api-lint has nothing to lint and there are no contract tests (server rule 18).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 an OpenAPI contract per business API, passing just api-lint with no warnings, versioned per the gematik rules, and contract tests
<!-- AC:END -->
