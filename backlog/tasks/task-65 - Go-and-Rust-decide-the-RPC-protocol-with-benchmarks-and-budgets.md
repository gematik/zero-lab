---
id: TASK-65
title: 'Go and Rust: decide the RPC protocol with benchmarks and budgets'
status: To Do
assignee: []
created_date: 2026-10-14 20:43
updated_date: '2026-11-01T16:11:00Z'
labels:
  - go
  - rpc
  - design
dependencies: []
references:
  - docs/interop.md
  - go/docs/design.md
priority: medium
ordinal: 63000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The ti serve protocol is open (CBOR, protobuf, PKCS#11 semantics; RPC performance section of docs/interop.md), and there are no benchmarks or budgets for the native-or-RPC decision.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 protocol chosen with measurements against the dependency goal, latency and throughput budgets per method, and just bench on both sides
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Answered for the first ti helpers by TASK-120 (2026-10-20): JSON lines (measured in TASK-116: no difference in the median against length-prefixed binary at certificate-check sizes; binary had the tighter tail). CBOR stays open for bulk data.

2026-11-01: decision-10 keeps JSON lines for the first helpers; TASK-116 measured no difference in the median against length-prefixed binary at certificate-check sizes, binary had the tighter tail. Binary framing for bulk data stays open here.
<!-- SECTION:NOTES:END -->
