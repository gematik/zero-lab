---
id: TASK-292
title: 'oidf: metadata policy'
status: To Do
assignee: []
created_date: '2026-11-12T21:08:00Z'
labels: []
dependencies: []
ordinal: 308000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
No metadata_policy of a superior statement is applied to a subject's metadata; the name does not occur in go/oidf. Found by zeta-pdp-go, which needs it for the login of insured persons at a sektoral IDP (its TASK-54) or as named.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Policies of the operators OpenID Federation defines are applied; a metadata that violates a policy is refused
<!-- AC:END -->
