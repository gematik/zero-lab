---
id: TASK-420
title: 'Test data: ti-pkcs12 high-iter.p12 uses a high iteration count'
status: To Do
assignee: []
created_date: '2026-11-24T05:41:00Z'
labels:
  - testdata
dependencies: []
ordinal: 433000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
rust/ti-pkcs12/tests/fixtures/high-iter.p12 has the default 2048 iterations like every other fixture, so its name promises a case no test covers. Build it with a high iteration count (e.g. 600000 for PBKDF2), update tests/decode.rs, go-baseline.json and spec/pkcs12 references that describe it, and name the test after the requirement it proves.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 high-iter.p12 carries an iteration count clearly above the default, stated in PROVENANCE.md
- [ ] #2 A test asserts the iteration count is decoded and the file opens
- [ ] #3 Every consumer (decode.rs, go-baseline.json, spec/pkcs12 manifest and matrix) agrees
<!-- AC:END -->
