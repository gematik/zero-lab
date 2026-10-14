---
id: TASK-67
title: 'Shared specs for functions both sides implement: DPoP, JOSE, OpenID Federation'
status: To Do
assignee: []
created_date: '2026-10-14 20:43'
labels:
  - go
  - spec
dependencies: []
references:
  - go/docs/design.md
priority: medium
ordinal: 65000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Where Go and Rust implement the same function, a spec in spec/<topic> is the reference (Go and Rust section); only tsl-xmldsig and pkcs12 exist.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 spec/dpop and spec/oidf-sek (and JOSE where both implement it) with rules, result codes, corpus and CONFORMANCE.md, run by both implementations
<!-- AC:END -->
