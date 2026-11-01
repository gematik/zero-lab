---
id: TASK-57
title: 'Dependencies: two XML parsers (quick-xml and roxmltree) on hostile input'
status: To Do
assignee: []
created_date: 2026-10-14 20:43
updated_date: '2026-11-01T16:11:00Z'
labels:
  - ti-pki
  - ti-xmldsig
  - ti-connector-client
  - deps
milestone: m-0
dependencies:
  - TASK-166
references:
  - docs/conventions/dependencies.md
  - rust/docs/design.md
priority: medium
ordinal: 55000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
quick-xml (TSL, SOAP) and roxmltree (C14N) both parse hostile XML (design goal 8, reuse before adding).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 evaluated whether one parser can serve TSL, SOAP and C14N; consolidated, or the reason for two recorded
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
2026-11-01: resolved by TASK-166. With the detached TSL signature the trust path needs no canonicalization: roxmltree and the C14N code leave the workspace and one hardened XML reader parses the TSL and SOAP.
<!-- SECTION:NOTES:END -->
