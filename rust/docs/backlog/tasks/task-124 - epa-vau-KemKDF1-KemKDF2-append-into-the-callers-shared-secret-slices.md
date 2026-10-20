---
id: TASK-124
title: 'epa/vau: KemKDF1/KemKDF2 append into the caller''s shared-secret slices'
status: To Do
assignee: []
created_date: '2026-10-20 18:26'
labels:
  - go
  - epa
  - security
dependencies: []
priority: medium
ordinal: 135000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
go/epa/vau/key_exchange.go builds the HKDF input with ss := append(ss_e_ecdh, ss_e_kyber768...) (KemKDF1) and append(append(ecdhSS1, kemSS1...), append(ecdhSS2, kemSS2...)...) (KemKDF2). When a caller's first slice has spare capacity, append writes the KEM secret into the caller's backing array, overwriting whatever follows it; the result also aliases the caller's memory, so zeroing one zeroes the other. Build the input in a fresh buffer of exact length, and clear it after the derivation.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 KemKDF1 and KemKDF2 never write into their arguments; a test with slices of spare capacity proves it
- [ ] #2 the concatenated secret is cleared after HKDF
<!-- AC:END -->
