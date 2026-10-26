---
id: TASK-35
title: 'ZETA client: plan and prerequisites (DPoP, OAuth core, ti-zeta)'
status: To Do
assignee: []
created_date: '2026-10-11 11:48'
updated_date: '2026-10-11 11:51'
labels:
  - zeta
  - jwz
  - ti-oauth
  - parked
dependencies:
  - TASK-18
priority: low
ordinal: 40000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The last open item of the original Rust-as-core goal (doc-1 roadmap stages 2, 3 and 7): a ZETA client without the SDK. Prerequisites: jwz JWK Set fetch (TASK-18), a DPoP profile in jwz (RFC 9449: dpop+jwt, jkt, ath, nonce), a sans-I/O ti-oauth (PAR, PKCE, private_key_jwt, DPoP-bound tokens, refresh), then ti-zeta (protected-resource discovery RFC 9728, client registration/attestation as the ZETA spec asks, token flow) with a ti zeta command and e2e tests against zero-pdp and zero-pep-proxy (go/pdp/e2e harness). Per-request DPoP proofs are the consumer doc-1 names for ti serve (TASK-26). Start with a plan for approval: stages, spec versions, what the ZETA Guard expects.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 a staged plan with spec references approved by the user, tasks per stage in the backlog
- [ ] #2 first stage implemented and proven by HITL
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
2026-10-11: postponed by the user.
<!-- SECTION:NOTES:END -->
