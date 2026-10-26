---
id: TASK-133
title: 'ti-pki real world: the reference SMC-B''s OCSP responder is now TSL-listed'
status: Done
assignee: []
created_date: '2026-10-22 18:55'
updated_date: '2026-10-22 18:59'
labels:
  - ti-pki
  - test
dependencies: []
priority: high
ordinal: 144000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
live_smcb_end_to_end pinned that the ehca TSP answered for the reference SMC-B with a delegate of GEM.KOMP-CA51, accepted as same-TSP with one OcspResponderNotRfc6960 warning. Since 2026-10-22 the TSL lists that responder, so it is authorized as TslListed and the run has no warnings; the test fails and blocks the ti-cli 0.5.0 release gate.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 live_smcb_end_to_end pins the TslListed authorization of the end entity's responder and no warnings
- [x] #2 just real-world passes
<!-- AC:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
live_smcb_end_to_end pins the new state: the end entity's responder is TslListed, certified by GEM.KOMP-CA51 TEST-ONLY, and the run has no warnings. The same-TSP delegate rule stays covered by ti-pki's unit tests. just real-world passes (3/3) on 2026-10-22.
<!-- SECTION:FINAL_SUMMARY:END -->
