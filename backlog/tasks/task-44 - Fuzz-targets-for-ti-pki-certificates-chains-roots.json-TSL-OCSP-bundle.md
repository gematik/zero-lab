---
id: TASK-44
title: 'Fuzz targets for ti-pki: certificates, chains, roots.json, TSL, OCSP, bundle'
status: Done
assignee: []
created_date: 2026-10-14 20:42
updated_date: '2026-11-05T20:34:00Z'
labels:
  - ti-pki
  - fuzz
dependencies: []
references:
  - docs/design/testing.md
  - rust/docs/design.md
priority: medium
ordinal: 42000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Design goal 9: every reader of attacker-chosen bytes has a fuzz target. ti-pki parses certificates, roots.json, the TSL (quick-xml) and OCSP responses from outside before any signature is checked, and the offline bundle. Layout as jwz/fuzz (docs/design/testing.md, Fuzzing; layout in rust/docs/design.md, Fuzzing).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 a fuzz crate ti-pki/fuzz with one target per entry point, committed seeds from spec corpora and real TI artefacts, invariants beyond no-panic, and just fuzz-ti-pki
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
ti-pki/fuzz had targets for the detached signature, the TSL XML, OCSP responses and the bundle; added certificate (any bytes as DER and PEM: decoding the certificate's own DER again gives the same value, every accessor validation and type detection read answers) and roots_json (parse, then the A_28419 walk from the embedded GEM.RCA7 TEST-ONLY anchor errors or starts at it). Seeds: four test PKI certificates and the embedded anchor; gematik's published roots.json for prod and nonprod. just fuzz-ti-pki runs all six; 20 s each on 2026-11-05, no crash.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
ti-pki has a fuzz target for each of its readers of outside bytes, certificates and roots.json added, with seeds and invariants beyond no-panic, run by just fuzz-ti-pki.
<!-- SECTION:FINAL_SUMMARY:END -->
