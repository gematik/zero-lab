---
id: TASK-131
title: 'pep: resource server nonces (RFC 9449 Section 9)'
status: Done
assignee: []
created_date: 2026-10-21 07:53
updated_date: '2026-11-05T20:20:00Z'
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
- [x] #1 nonce_required works: a proof without the current nonce is answered 401 use_dpop_nonce with DPoP-Nonce, one with it is accepted, across replicas
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
pep: Builder.WithDPoPNonces(dpop.NonceSource); with nonce_required, the verifier with nonces checks the proof, a missing or unknown nonce is 401 use_dpop_nonce with DPoP-Nonce, and accepted requests get the next one, with Cache-Control no-store and Access-Control-Expose-Headers. Without a source, nonce_required still refuses with internal_error. Replicas share keys, not a store: nonce.Source seals its nonces. zaddy: dpop_nonce_keyring_path (kv keyring) in the pep block, else an ephemeral key with a warning. Tests: four RFC9449_9 tests in pep/nonce_test.go, two replicas on shared keys among them. zaddy's tagged build needs just sync, as its go.mod pins pep at a pseudo-version without WithDPoPNonces.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
pep supports resource server DPoP nonces (RFC 9449 Section 9) through a nonce source the replicas share by key; zaddy configures it with an optional keyring.
<!-- SECTION:FINAL_SUMMARY:END -->
