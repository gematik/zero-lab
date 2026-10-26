---
id: TASK-131
title: 'pep: resource server nonces (RFC 9449 Section 9)'
status: To Do
assignee: []
created_date: '2026-10-21 07:53'
labels:
  - go
  - pep
dependencies: []
priority: low
ordinal: 142000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
pep's authorization_dpop enforcer has nonce_required, which today refuses every request with 500 'Nonce required but not implemented'. Implement it with go/dpop's NonceSource: unpredictable nonces valid for a window, shared by the replicas (kv), handed out in DPoP-Nonce on 401 use_dpop_nonce and on successful responses (Section 8.2), with Access-Control-Expose-Headers where browsers call the resource.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 nonce_required works: a proof without the current nonce is answered 401 use_dpop_nonce with DPoP-Nonce, one with it is accepted, across replicas
<!-- AC:END -->
