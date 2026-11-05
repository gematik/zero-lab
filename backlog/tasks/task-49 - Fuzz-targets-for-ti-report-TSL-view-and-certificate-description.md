---
id: TASK-49
title: 'Fuzz targets for ti-report: TSL view and certificate description'
status: Done
assignee: []
created_date: 2026-10-14 20:42
updated_date: '2026-11-05T21:05:00Z'
labels:
  - ti-report
  - wasm
  - fuzz
dependencies: []
references:
  - docs/design/testing.md
  - rust/docs/design.md
priority: medium
ordinal: 47000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Design goal 9. ti-report is what ti-wasm hands hostile bytes to in the browser.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 fuzz targets for verify_tsl and describe_certificate inputs, seeded from the TSL fixtures, and a just recipe
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
rust/ti-report/fuzz drives ti_wasm::api, the functions a web page reaches: describe_certificate (any bytes as DER or PEM; the answer is a JSON object), verify_tsl (any bytes as the TSL with the reference environment's published signature and signer status: never valid unless the bytes are the signed list) and verify_tsl_roots (any bytes as the supplied roots.json next to the published set: the verdict stays the embedded roots' one, which the target first checks is valid). Seeds: the test PKI's certificates, ti-pki's TSL seeds, the nonprod roots.json and an empty list. just fuzz-ti-report; 30 s each on 2026-11-05, no crash. verify_tsl_roots verifies the whole 570 KB list per run, about 4 runs a second.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
ti-report has fuzz targets for what ti-wasm hands it from a web page: certificates, the TSL and a supplied roots.json, with invariants on the verdict, run by just fuzz-ti-report.
<!-- SECTION:FINAL_SUMMARY:END -->
