---
id: TASK-339
title: 'SPIKE: ZETA/ASL and ePA VAU on the Go standard library'
status: In Progress
assignee: []
created_date: '2026-11-15T16:31:00Z'
updated_date: '2026-11-15T17:38:00Z'
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
- [x] #1 Kyber v3.02 on crypto/mlkem: differential test against circl, decapsulation KATs, and a live ePA connect with circl out of the non-test code
- [x] #2 An ASL profile (ML-KEM-768, ZETA-ASL-* headers, /ASL) completes a handshake and data records against the package's own server; interop with gematik's libasl tried or its cost stated
- [x] #3 A strict CBOR subset prototype with a differential fuzz against fxamacker, its size measured
- [x] #4 A backlog document with the verdict per question, the evidence and proposed follow-up tasks
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Result in doc-5. Branch spike/asl-stdlib at b5cabec9 (not merged): circl and fxamacker out of go/epa non-test code; live ePA connect RU provider 2 passed on it; libasl interop both ways. Awaiting the maintainer decision on the follow-ups listed in doc-5.
<!-- SECTION:NOTES:END -->
