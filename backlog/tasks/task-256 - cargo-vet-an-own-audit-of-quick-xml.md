---
id: TASK-256
title: 'cargo-vet: an own audit of quick-xml'
status: To Do
assignee: []
created_date: '2026-11-07T17:19:00Z'
labels:
  - deps
  - supply-chain
  - security
dependencies: []
priority: medium
ordinal: 272000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
quick-xml 0.42 parses hostile XML in two cores (the TSL in ti-pki, SOAP responses in ti-connector-client) and is only exempted; no imported audit covers it. An own audit needs a person to certify it (cargo vet certify records who). Found in TASK-224.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 quick-xml is covered by an own or imported audit at safe-to-deploy, or the exemption note says why not
<!-- AC:END -->
