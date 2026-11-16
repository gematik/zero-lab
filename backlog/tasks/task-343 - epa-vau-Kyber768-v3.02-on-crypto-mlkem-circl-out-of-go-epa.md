---
id: TASK-343
title: 'epa/vau: Kyber768 v3.02 on crypto/mlkem, circl out of go/epa'
status: To Do
assignee: []
created_date: '2026-11-16T18:21:00Z'
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
- [ ] #1 go list -deps ./epa/... names circl only through test packages; the differential tests against circl and the Kyber fuzz targets pass
- [ ] #2 TestEPA_Connect passes against the reference environment on the branch, and epa is released
<!-- AC:END -->
