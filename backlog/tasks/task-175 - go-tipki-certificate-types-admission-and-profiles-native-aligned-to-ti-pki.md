---
id: TASK-175
title: 'go/tipki: certificate types, admission and profiles, native, aligned to ti-pki'
status: In Progress
assignee: []
created_date: '2026-11-02T06:07:00Z'
updated_date: '2026-11-02T06:13:00Z'
labels:
  - go
  - pki
dependencies: []
priority: high
ordinal: 185000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Maintainer, 2026-11-02: critical flows use the smallest possible Go-native libraries; admission and certificate profiles come back from the archived gempki, aligned to rust/ti-pki rather than to the old concept. No chain, TSL or OCSP here: it reads a certificate and decides nothing about trust.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 spec/pki-profiles with rules, a corpus ti-pki writes and go/tipki runs, and a traceability table
- [x] #2 go/tipki has no dependencies and no chain, TSL or OCSP code
- [x] #3 the parser has a fuzz target
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
2026-11-02: built on feat/go-tipki. Tables, 41 certificates and 38 admission values match ti-pki; the corpus found one difference on the first run, Go refusing BMPString items, settled for Rust. A real test SMC-B on brainpool, parsed by go/brainpool, reads as C.HCI.AUT, profile hci-aut, with no findings. Reads certificates only: TASK-171 still needs chain, TSL and OCSP, which the maintainer decides per flow.
<!-- SECTION:NOTES:END -->
