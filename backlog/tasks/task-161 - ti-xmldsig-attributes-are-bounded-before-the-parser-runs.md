---
id: TASK-161
title: 'ti-xmldsig: attributes are bounded before the parser runs'
status: Done
assignee: []
created_date: '2026-11-01T13:53:00Z'
updated_date: '2026-11-01T14:09:00Z'
labels:
  - ti-xmldsig
  - security
dependencies: []
priority: high
ordinal: 172000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Found in TASK-57. roxmltree checks an element's attributes for duplicates pairwise, so its time grows with the square of their number, and Document::parse only counted them after the parser ran. Through ti_pki::tsl_signature::verify, before any signature is checked: 80,000 attributes (848 KB) take 6 s, 200,000 (2.2 MB) take 32 s, and the 16 MiB limit allows far more. TSLSIG-001 already bounds attributes and requires depth to be bounded before the parser descends.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 A start tag with more attributes and namespace declarations than the limits allow is refused before the parser runs, with a test named after the rule
- [x] #2 Worst cases within 16 MiB through tsl_signature::verify are measured and take well under a second to a few seconds
<!-- AC:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Document::parse refuses a start tag with more than max_attributes + max_namespaces assignments before roxmltree runs. Through tsl_signature::verify, 200,000 attributes took 32 s before; now 1.4M namespace declarations in 15.7 MB are refused in 28 ms, and the slowest other case within 16 MiB (siblings with 64 attributes each) takes 0.35 s. Those inputs stop before the signature is checked. The Kani proof depth_scan_is_total still holds on the shared scan; just check green. Upstream roxmltree is not reported yet.
<!-- SECTION:FINAL_SUMMARY:END -->
