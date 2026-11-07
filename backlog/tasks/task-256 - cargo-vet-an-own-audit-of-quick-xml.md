---
id: TASK-256
title: 'cargo-vet: an own audit of quick-xml'
status: Done
assignee: []
created_date: '2026-11-07T17:19:00Z'
updated_date: '2026-11-07T18:54:00Z'
labels:
  - deps
  - supply-chain
  - security
dependencies: []
priority: medium
ordinal: 272000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
quick-xml 0.42 parses hostile XML in two cores (the TSL in ti-pki, SOAP responses in ti-connector-client) and is only exempted; no imported audit covers it. An own audit needs a person to certify it (cargo vet certify records who). Found in TASK-224.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 quick-xml is covered by an own or imported audit at safe-to-deploy, or the exemption note says why not
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Reviewed quick-xml 0.42.0: #![forbid(unsafe_code)], unsafe only in comments; no build.rs; no network or process access, std::fs only in Reader::from_file (unused); dependencies in our build memchr (approved unsafe exception) and serde (serialize), plus overlapped-lists. Maintainer keeps it exempted rather than certifying; the exemption note records the review.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
quick-xml 0.42.0 reviewed (forbid(unsafe_code), no build script, no I/O in use, memchr and serde only); the maintainer keeps it exempted rather than certifying, and the exemption note records the review.
<!-- SECTION:FINAL_SUMMARY:END -->
