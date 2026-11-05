---
id: TASK-94
title: 'Go deps: explicit Validate methods instead of go-playground/validator'
status: In Progress
assignee: []
created_date: 2026-10-14 20:44
updated_date: '2026-11-05T18:35:00Z'
labels:
  - go
  - deps
  - pdp
dependencies: []
references:
  - docs/conventions/dependencies.md
  - go/docs/design.md
priority: medium
ordinal: 92000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
validator works by reflection over about 67 struct tags and brings about 20 modules; explicit methods are easier to review for the authorization server.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 validator removed; request types validate themselves explicitly with tests per rule
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
go/epa's configuration was the last user: Config and ProxyConfig have explicit Validate methods with a test per rule, and validator, mimetype and what only they needed left its go.mod. One rule is stricter: proxies: [] is refused, where required let an empty list through. Errors name the setting, never its value.
<!-- SECTION:NOTES:END -->
