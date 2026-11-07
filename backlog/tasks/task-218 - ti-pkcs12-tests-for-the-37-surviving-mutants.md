---
id: TASK-218
title: 'ti-pkcs12: tests for the 37 surviving mutants'
status: Done
assignee: []
created_date: '2026-11-05T21:53:00Z'
updated_date: '2026-11-07T18:54:00Z'
labels:
  - tests
  - ti-pkcs12
dependencies: []
ordinal: 225000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
cargo-mutants 27.1.0 on ti-pkcs12 (default features, main at e15366b0): 37 missed, 136 caught, 5 timeouts, 54 unviable, score 79.2% against the proposed threshold of 80% (TASK-53). Among the survivors: Error::is_wrong_password returning a constant, the KEY_BAG and SAFE_CONTENTS_BAG arms of collect and the TRUSTED_KEY_USAGE arm of attributes deleted, the length guard of is_pkcs12, asn1::one, the EncryptedData version check, and the PKCS#12 PBE guard in decrypt. Full list: just mutants ti-pkcs12, mutants.out/missed.txt.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 each surviving mutant is killed by a test named after the rule it breaks, or marked equivalent with the reason
- [x] #2 just mutants-record ti-pkcs12 reaches the crate's threshold
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
All 17 survivors of the --all-features run killed (tests named after P12-012, P12-013, P12-033, RFC 5652 §8, is_wrong_password, is_pkcs12 length forms, names); the < vs <= mutant in is_pkcs12 removed by matching the length as a range. Recorded at f8704786 (with TASK-255): 161 caught, 6 timeouts, 0 missed, 60 unviable, score 1.0.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Tests for every surviving ti-pkcs12 mutant (P12-012, P12-013, P12-033, RFC 5652 §8, is_wrong_password, is_pkcs12 length forms, reported names); one equivalent mutant removed by matching the length as a range. Score recorded with just mutants-record: 1.0 (161 caught, 6 timeouts, 0 missed). Full just check green before the merge.
<!-- SECTION:FINAL_SUMMARY:END -->
