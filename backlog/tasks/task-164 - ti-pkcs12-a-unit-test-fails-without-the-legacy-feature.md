---
id: TASK-164
title: 'ti-pkcs12: a unit test fails without the legacy feature'
status: To Do
assignee: []
created_date: '2026-11-01T15:18:00Z'
labels:
  - ti-pkcs12
  - testing
dependencies: []
priority: low
ordinal: 174000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Found in TASK-56, already so before it. cargo test -p ti-pkcs12 --no-default-features --features encode --lib fails in encode::tests::round_trips_through_decode: its fixture is a legacy file (PBE_SHA1_3DES), which that build refuses with UnsupportedAlgorithm. just check does not run this combination.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The test passes or is gated without legacy, and that feature combination is tested
<!-- AC:END -->
