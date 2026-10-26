---
id: TASK-100
title: 'Propose the business-API scope and fixes to the gematik OpenAPI ruleset'
status: To Do
assignee: []
created_date: '2026-10-15 05:35'
labels:
  - api
  - spec
  - upstream
dependencies:
  - TASK-99
references:
  - docs/design/servers.md
priority: medium
ordinal: 98000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The gematik ruleset (dev-portal/api-tools, d698980) does not say that it applies to business APIs only, so protocol APIs (OAuth 2.0, OIDC) linted with it produce findings their standards forbid fixing. It also has known problems: path-must-include-version accepts only /v1/; headers-hyphenated-pascal-case is anchored only at the start (lowercase names pass, standard names such as DPoP warn); must-use-standard-http-status-codes lacks 308 and 422; ensureSnakeCaseWithDigits is declared but unused.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 a merge request to dev-portal/api-tools that states the ruleset's scope (business APIs; protocol APIs follow their standards) in rules-explained.md
- [ ] #2 merge requests for a v[0-9]+ version pattern, an anchored header pattern, 308 and 422, and the unused function; the pin in go/Justfile moves when they are merged
<!-- AC:END -->
