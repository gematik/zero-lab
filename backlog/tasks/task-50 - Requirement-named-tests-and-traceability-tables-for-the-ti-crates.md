---
id: TASK-50
title: Requirement-named tests and traceability tables for the ti crates
status: To Do
assignee: []
created_date: '2026-10-14 20:42'
labels:
  - tests
  - spec
dependencies:
  - TASK-14
references:
  - docs/design/testing.md
priority: medium
ordinal: 48000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
docs/design/testing.md, Tests name the requirement they prove: tests carry the requirement ID in their name and code cites it. Only jwz has a traceability table today.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 tests of security rules in ti-pki, ti-xmldsig, ti-pkcs12, ti-idpd, ti-directory and ti-connector-client named after their requirement, and a generated, checked traceability table per crate like jwz's
<!-- AC:END -->
