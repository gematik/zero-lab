---
id: TASK-158
title: 'spec/pkcs12: a work budget per file, not only per iteration count'
status: To Do
assignee: []
created_date: '2026-10-29T12:04:00Z'
labels:
  - spec
  - security
  - rust
  - go
dependencies: []
references:
  - spec/pkcs12/README.md
priority: medium
ordinal: 169000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
P12-036 caps each iteration count (MAC, PKCS#12 KDF, PBKDF2) at 10,000,000, but not their sum: a crafted file with many shrouded keys or encrypted safes costs up to 10M iterations each, seconds per bag. Found while writing the fuzz target (TASK-46). Decide a total budget (e.g. sum of iterations per decode, or a bound on derivations) in spec/pkcs12 and apply it in go/pkcs12 and rust/ti-pkcs12.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 spec/pkcs12 states a total work budget per decode with its result code (limit_exceeded), checked before the derivation that would exceed it
- [ ] #2 conformance case in testdata/manifest.json with many bags under the per-count limit but over the total
- [ ] #3 go/pkcs12 and rust/ti-pkcs12 implement it; interop matrix regenerated
- [ ] #4 Tests named after the requirement
<!-- AC:END -->
