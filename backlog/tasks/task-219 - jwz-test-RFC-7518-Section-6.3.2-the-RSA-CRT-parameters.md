---
id: TASK-219
title: 'jwz: test RFC 7518 Section 6.3.2, the RSA CRT parameters'
status: Done
assignee: []
created_date: '2026-11-05T21:53:00Z'
updated_date: '2026-11-05T22:12:00Z'
labels:
  - jwz
  - tests
dependencies: []
ordinal: 226000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
just coverage jwz (TASK-54): the check that p, q, dp, dq and qi come together or not at all (jwk.rs, RFC 7518 Section 6.3.2) runs in no test.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 a test named rfc_7518_6_3_2_… proves a partial set of CRT parameters is refused
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Covered by TASK-51: rfc_7518_6_3_2_crt_parameters_come_together_or_not_at_all (f19c1e2e).
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Covered by TASK-51's rfc_7518_6_3_2_crt_parameters_come_together_or_not_at_all.
<!-- SECTION:FINAL_SUMMARY:END -->
