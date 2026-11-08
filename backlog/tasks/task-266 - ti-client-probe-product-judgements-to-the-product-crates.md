---
id: TASK-266
title: 'ti-client probe: product judgements to the product crates'
status: To Do
assignee: []
created_date: '2026-11-08T06:34:00Z'
labels:
  - rust
dependencies: []
ordinal: 282000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
ti_client::probe judges the OIDC issuer, the directory redirect, ePA/eRP/ZETA answers and holds the endpoint catalog. They are reachability checks, but per decision-15 product knowledge belongs to the product crates. Decide per judgement where it belongs and move it. Found during TASK-250.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 each judgement is in its product crate or noted why it is host connectivity
<!-- AC:END -->
