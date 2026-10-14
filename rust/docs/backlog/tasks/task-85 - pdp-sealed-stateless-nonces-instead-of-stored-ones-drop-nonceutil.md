---
id: TASK-85
title: 'pdp: sealed stateless nonces instead of stored ones; drop nonceutil'
status: To Do
assignee: []
created_date: '2026-10-14 20:44'
labels:
  - go
  - pdp
  - nonce
dependencies: []
references:
  - go/docs/design.md
priority: medium
ordinal: 83000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
pdp stores every nonce in kv; HashicorpNonceService seals with a per-process key, so nonces fail across replicas (server rule 10).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 one sealed nonce (AEAD over issue time, purpose and binding) under a shared workload key, verified without a lookup; nonceutil removed
<!-- AC:END -->
