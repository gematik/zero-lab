---
id: TASK-47
title: >-
  Fuzz targets for ti-connector-client: .kon files, SOAP responses and faults,
  service directory
status: Done
assignee: []
created_date: 2026-10-14 20:42
updated_date: '2026-11-01T13:36:00Z'
labels:
  - ti-connector-client
  - fuzz
milestone: m-0
dependencies: []
references:
  - docs/design/testing.md
  - rust/docs/design.md
priority: medium
ordinal: 45000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Design goal 9. A Konnektor's answers and the .kon file are input from outside.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 ti-connector-client/fuzz with targets for Dotkon::parse, the SOAP decoding and the service directory, seeded from the recorded runs, and a just recipe
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Targets dotkon (TASK-136), sds and soap; sds and soap are seeded from tests/fixtures, recorded runs included, so no second copy. soap goes through the public calls over a transport that returns the fuzz bytes: no API for tests, and the code after decoding runs as well; 20 calls, not every operation. Runs without a crash on the final code: 30 s each in the recipe, plus 150 s of fuzzing each for soap and sds (8,700 and 78,025 runs). The slow units of 429 and 293 s were the machine asleep (pmset log; each input takes 2-10 ms alone). Found: rewrite_endpoints left HTTPS://… and non-URLs in place, fixed with a regression test. Without rewrite, the directory still decides where credentials go: TASK-160.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
ti-connector-client/fuzz has targets for the .kon file, the service directory and every main Konnektor call on any answer; just fuzz-ti-connector-client runs all three. The target sds found that rewrite_endpoints could leave an endpoint outside the .kon origin; fixed with a regression test. just check green. TASK-160 covers the case without rewrite.
<!-- SECTION:FINAL_SUMMARY:END -->
