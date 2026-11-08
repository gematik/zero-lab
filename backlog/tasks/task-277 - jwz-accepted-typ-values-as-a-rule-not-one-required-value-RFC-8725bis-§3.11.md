---
id: TASK-277
title: 'jwz: accepted typ values as a rule, not one required value (RFC 8725bis §3.11)'
status: To Do
assignee: []
created_date: '2026-11-08T15:20:00Z'
labels:
  - jwz
dependencies: []
priority: low
ordinal: 293000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Found by TASK-258. Policy::typ is one required value. draft-ietf-oauth-rfc8725bis-10 §3.11 describes verifiers that accept a set of explicit types, or require a match only when typ is present. A small rule type in place of Option<String> would express it.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Policy states the accepted typ values and whether typ is required; the existing behaviour is one case of it
- [ ] #2 tests named after the draft section; the draft revision pinned
<!-- AC:END -->
