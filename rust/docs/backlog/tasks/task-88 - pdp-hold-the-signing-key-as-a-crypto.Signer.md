---
id: TASK-88
title: 'pdp: hold the signing key as a crypto.Signer'
status: To Do
assignee: []
created_date: '2026-10-14 20:44'
labels:
  - go
  - pdp
  - keys
dependencies: []
references:
  - go/docs/design.md
priority: medium
ordinal: 86000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
pdp/authzserver holds its signing key as a jwk.Key loaded from a file (private-key rule 1).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 the AS signs through a crypto.Signer created at the edge; no private JWK held in the server
<!-- AC:END -->
