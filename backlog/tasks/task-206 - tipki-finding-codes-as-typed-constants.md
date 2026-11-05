---
id: TASK-206
title: 'tipki: finding codes as typed constants'
status: Done
assignee: []
created_date: '2026-11-03T17:59:00Z'
updated_date: '2026-11-05T19:19:00Z'
labels:
  - tipki
dependencies: []
ordinal: 213000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Finding.Code is a plain string and codes are literals where a finding is made, so a typo in a code the corpus does not produce goes unnoticed and callers compare raw strings. ti-pki has an ErrorCode enum. Give tipki a typed code with exported constants, named after ti-pki's.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Every code tipki puts in a Finding is an exported constant of one type
- [x] #2 The constants' values are ti-pki's wire codes, pinned against it
- [x] #3 No finding is made with a string literal as its code
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
ErrorCode, named after ti-pki's, with constants for all 25 codes. Finding and OCSPError carry it. TSLError keeps its string codes: a separate family, not findings. CodeProfileNotDetected and CodeProfileAmbiguous are declared for ti-pki's list but no finding uses them. A literal still compiles, so TestNoFindingIsMadeWithALiteralCode reads the source. Rust's list goes into the corpus (PROF-032).
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
tipki's finding codes are typed constants, released as v0.31.0.
<!-- SECTION:FINAL_SUMMARY:END -->
