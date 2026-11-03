---
id: TASK-207
title: 'pkcs12: trim the API before v1.0.0'
status: In Progress
assignee: []
created_date: '2026-11-03T18:25:00Z'
updated_date: '2026-11-03T18:30:00Z'
labels:
  - pkcs12
dependencies: []
ordinal: 214000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
v1.0.0 is a stability promise, and removing anything public afterwards takes a /v2 module path. Remove the deprecated legacy.ConvertWithOpenSSL and what no consumer needs from the low-level Parse and Decrypt surface.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 legacy.ConvertWithOpenSSL is gone
- [x] #2 Every exported identifier has a consumer or is the documented API
- [x] #3 Decode results are unchanged: the interop matrix still passes
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Outside the module only Decode was called directly (ehca, idpd); the interop adapter also used Parse. The layers moved to internal/syntax, ber and rc2 to internal; ConvertWithOpenSSL, IsBER and ErrInvalidMAC are gone. legacy.Parse is new, because the adapter needed it and a legacy user had no way to insist on a MAC. TestThePublicAPIIsTheDocumentedOne pins the list. Interop after the change: 56 of 56 for Go and Rust, 28 of 28 modern.
<!-- SECTION:NOTES:END -->
