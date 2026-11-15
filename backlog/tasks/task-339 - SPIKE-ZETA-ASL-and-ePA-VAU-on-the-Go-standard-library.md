---
id: TASK-339
title: 'SPIKE: ZETA/ASL and ePA VAU on the Go standard library'
status: In Progress
assignee: []
created_date: '2026-11-15T16:31:00Z'
labels: []
dependencies: []
ordinal: 354000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Can ZETA/ASL (gemSpec_Krypt chapter 7, the ePA VAU protocol with ML-KEM-768) and ePA VAU itself (Kyber768 v3.02) be built with only the Go standard library? Main question: the KEM. ASL's ML-KEM-768 is crypto/mlkem; Kyber v3.02 may be built from crypto/mlkem and crypto/sha3 (gematik lib-vau does the same from an ML-KEM implementation), which would drop circl (TASK-96 kept it). Second: CBOR, which the standard library lacks. Plan: /Users/serg/.claude/plans/cheerful-tickling-bear.md. Work on branch spike/asl-stdlib; no merge without the maintainer's decision.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Kyber v3.02 on crypto/mlkem: differential test against circl, decapsulation KATs, and a live ePA connect with circl out of the non-test code
- [ ] #2 An ASL profile (ML-KEM-768, ZETA-ASL-* headers, /ASL) completes a handshake and data records against the package's own server; interop with gematik's libasl tried or its cost stated
- [ ] #3 A strict CBOR subset prototype with a differential fuzz against fxamacker, its size measured
- [ ] #4 A backlog document with the verdict per question, the evidence and proposed follow-up tasks
<!-- AC:END -->
