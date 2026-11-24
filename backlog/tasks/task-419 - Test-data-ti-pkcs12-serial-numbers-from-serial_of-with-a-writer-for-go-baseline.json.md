---
id: TASK-419
title: >-
  Test data: ti-pkcs12 serial numbers from serial_of, with a writer for
  go-baseline.json
status: To Do
assignee: []
created_date: '2026-11-24T05:41:00Z'
labels:
  - testdata
dependencies: []
ordinal: 432000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
rust/ti-pkcs12/tests/fixtures/generate_test_data.sh keeps the three historic certificates' serial numbers (TASK-412), because go-baseline.json pins them and nothing writes that file. Give go-baseline.json a generator (a small Go program run from the generator, standard library only), then switch the serials to serial_of from spec/fixtures.sh with one FORCE=1 rebuild.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 go-baseline.json is written by a documented command, never by hand
- [ ] #2 Every serial number in the generator comes from serial_of
- [ ] #3 A plain run changes no file; FORCE=1 reproduces every byte except the named randomised outputs
- [ ] #4 ti-pkcs12 tests pass with all and default features
<!-- AC:END -->
