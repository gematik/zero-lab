---
id: TASK-349
title: 'epa: circl out of the tests too'
status: Done
assignee: []
created_date: '2026-11-16T20:28:00Z'
updated_date: '2026-11-16T20:30:00Z'
labels: []
dependencies: []
ordinal: 364000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
decision-18 left circl as the test comparison for Kyber768 v3.02 (TASK-343). The maintainer wants it gone completely (2026-11-16). Replace the live differential test with fixed vectors produced once by circl's kyber768 (deterministic encapsulation to ML-KEM-generated keys: seed d‖z, ciphertext, shared secret; and Kyber-generated public keys that ML-KEM must accept), committed under go/epa/vau/testdata, and drop circl from go/epa/go.mod. zaddy keeps circl indirectly through Caddy's caddytls (HPKE for Encrypted Client Hello); that is not ours to remove.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 go/epa/go.mod and go.sum name no circl; no Go file in go/epa imports it
- [x] #2 Committed vectors from circl's Kyber768 v3.02 decapsulate to the recorded shared secret with the standard-library construction, and Kyber public keys are accepted; the generator is described in the test's comment
<!-- AC:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
go/epa names no circl in go.mod, go.sum or any test; Kyber768 v3.02 is tested on committed circl vectors (decapsulation and public keys) plus a self round trip; zaddy keeps circl indirectly through Caddy caddytls (HPKE for ECH).
<!-- SECTION:FINAL_SUMMARY:END -->
