---
id: TASK-343
title: 'epa/vau: Kyber768 v3.02 on crypto/mlkem, circl out of go/epa'
status: Done
assignee: []
created_date: '2026-11-16T18:21:00Z'
updated_date: '2026-11-16T20:25:00Z'
labels: []
dependencies: []
ordinal: 358000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
decision-18. Take the construction from spike/asl-stdlib commit 27ae33da (kyber.go, kem.go, key_exchange.go, kyber_test.go): shared secret SHAKE256(K ‖ SHA3-256(c), 32) over crypto/mlkem ML-KEM-768. circl stays only as the test comparison. Supersedes TASK-96 on circl.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 go list -deps ./epa/... names circl only through test packages; the differential tests against circl and the Kyber fuzz targets pass
- [x] #2 TestEPA_Connect passes against the reference environment on the branch, and epa is released
<!-- AC:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Kyber768 v3.02 on crypto/mlkem and crypto/sha3; circl only as the test comparison. Differential tests both ways, fuzz targets, live ePA connect and entitlement passed. Released in epa v0.27.0.
<!-- SECTION:FINAL_SUMMARY:END -->
