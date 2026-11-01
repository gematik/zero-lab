---
id: TASK-57
title: 'Dependencies: two XML parsers (quick-xml and roxmltree) on hostile input'
status: Done
assignee: []
created_date: 2026-10-14 20:43
updated_date: '2026-11-01T16:11:00Z'
labels:
  - ti-pki
  - ti-xmldsig
  - ti-connector-client
  - deps
milestone: m-0
dependencies: []
references:
  - docs/conventions/dependencies.md
  - rust/docs/design.md
priority: medium
ordinal: 55000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
quick-xml (TSL, SOAP) and roxmltree (C14N) both parse hostile XML (design goal 8, reuse before adding).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 evaluated whether one parser can serve TSL, SOAP and C14N; consolidated, or the reason for two recorded
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Evaluated with hostile input, measured: no consolidation. roxmltree cannot serve SOAP or the service directory: read-only, no serde, and 17,000 lines of generated types use serde both ways. quick-xml cannot serve C14N: no tree with namespace scopes, no refusal of a DTD. Only the TSL could move to roxmltree, which takes quick-xml out of ti-pki but not out of the tree. A verified TSL is parsed from the signed canonical bytes, so no parser differential on what was signed. Results at up to 7 MB (deep nesting, unclosed tags, siblings, billion laughs, external entity): both refuse or finish under 100 ms, no entity expanded. Exception: roxmltree's attributes are quadratic, TASK-161. quick-xml accepts and skips a DTD; roxmltree refuses it. Both are 0.x, maintained; roxmltree 0.21.2 is out, not taken here.
2026-11-01: this evaluation holds for today's tree. TASK-166 verifies the TSL by its detached signature, and removing the XMLDSig path behind its gate takes roxmltree and the C14N code out, leaving quick-xml; the decision to remove is TASK-166's.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Two XML parsers stay; the reason is next to them in rust/Cargo.toml, and rust/docs/design.md no longer says all XML goes through roxmltree. The review found TASK-161.
<!-- SECTION:FINAL_SUMMARY:END -->
