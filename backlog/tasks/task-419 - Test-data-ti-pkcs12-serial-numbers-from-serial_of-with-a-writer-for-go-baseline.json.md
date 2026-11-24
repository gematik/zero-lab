---
id: TASK-419
title: >-
  Test data: ti-pkcs12 serial numbers from serial_of, with a writer for
  go-baseline.json
status: Done
assignee: []
created_date: '2026-11-24T05:41:00Z'
updated_date: '2026-11-24T20:04:00Z'
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
- [x] #1 go-baseline.json is written by a documented command, never by hand
- [x] #2 Every serial number in the generator comes from serial_of
- [x] #3 A plain run changes no file; FORCE=1 reproduces every byte except the named randomised outputs
- [x] #4 ti-pkcs12 tests pass with all and default features
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
2026-11-24, on chore/pkcs12-testdata. go-baseline.json is written by rust/ti-pkcs12/tests/fixtures/baseline (a Go module of its own beside the fixtures, go/pkcs12 by replace and the standard library, as spec/pkcs12/interop/go), which generate_test_data.sh runs on every run (just test-pkcs12 in rust/). Against the committed file the writer first gave the same certificates, keys and pairs, with two differences kept: the BER vendor files are read natively by legacy.Decode, so their entries carry the file's own friendlyName, localKeyId and key encoding instead of an OpenSSL re-export's (tests/decode.rs drops its exception for them and compares everything); and an error is the conformance code (malformed), not go/pkcs12's wording, so rewording Go's errors or new random data does not change the file. Serial numbers from serial_of (ca, server, ec), one FORCE=1 rebuild with OpenSSL 4.1.0. Verified: a plain run changes no file; a second FORCE=1 changes only the nine .p12 files and random.p12; ti-pkcs12 tests pass with all, default and no default features; just check-changed passes. shellcheck is not installed here, the script was not linted.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
go-baseline.json is written by rust/ti-pkcs12/tests/fixtures/baseline (Go, go/pkcs12 and the standard library) on every run of generate_test_data.sh (just test-pkcs12); serial numbers come from serial_of; the BER vendor files are in the baseline as go/pkcs12 reads them natively, errors as conformance codes. Verified: a plain run changes no file, FORCE=1 changes only the .p12 files and random.p12, ti-pkcs12 tests with all, default and no default features, full just check in rust/. Not done: shellcheck of the script (not installed). Merged in 134ce5f2.
<!-- SECTION:FINAL_SUMMARY:END -->
