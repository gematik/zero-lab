---
id: TASK-56
title: 'Dependencies: scrypt and salsa20 through pkcs5''s pbes2 feature'
status: To Do
assignee: []
created_date: 2026-10-14 20:43
updated_date: '2026-10-26T15:44:00Z'
labels:
  - ti-pkcs12
  - deps
milestone: m-0
dependencies: []
references:
  - docs/conventions/dependencies.md
  - rust/docs/design.md
priority: medium
ordinal: 54000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
pkcs5's pbes2 feature pulls scrypt and salsa20, though PKCS#12 never needs scrypt (P12-030).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 scrypt and salsa20 out of the tree through a pkcs5 feature split, an upstream change, or a recorded known compromise
<!-- AC:END -->
