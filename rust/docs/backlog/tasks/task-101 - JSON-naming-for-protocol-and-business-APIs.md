---
id: TASK-101
title: 'JSON naming for protocol and business APIs'
status: To Do
assignee: []
created_date: '2026-10-15 05:35'
labels:
  - docs
  - api
dependencies:
  - TASK-99
references:
  - docs/conventions/naming-and-config.md
priority: medium
ordinal: 99000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The gematik ruleset has no rule for JSON property names. Protocol APIs take their member names from their standards (snake_case in OAuth 2.0 and OIDC); for business APIs the naming must be decided and written down. Today our own APIs are snake_case (pdp, pep, bff, the ti CLI contract), while epa mirrors the camelCase of the gematik ePA interfaces.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 docs/conventions/naming-and-config.md states the JSON naming per category: protocol APIs as their specification defines, business APIs by one decided convention (aligned with the gematik API guidelines), interfaces that mirror an upstream API as upstream names them
- [ ] #2 the language profiles name how it is enforced (serde rename_all, Go json tags)
<!-- AC:END -->
