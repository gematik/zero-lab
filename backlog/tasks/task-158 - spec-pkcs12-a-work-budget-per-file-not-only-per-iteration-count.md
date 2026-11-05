---
id: TASK-158
title: 'spec/pkcs12: a work budget per file, not only per iteration count'
status: Done
assignee: []
created_date: '2026-10-29T12:04:00Z'
updated_date: '2026-11-05T20:09:00Z'
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
- [x] #1 spec/pkcs12 states a total work budget per decode with its result code (limit_exceeded), checked before the derivation that would exceed it
- [x] #2 conformance case in testdata/manifest.json with many bags under the per-count limit but over the total
- [x] #3 go/pkcs12 and rust/ti-pkcs12 implement it; interop matrix regenerated
- [x] #4 Tests named after the requirement
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Budget chosen 2026-11-05: 10,000,000 iterations per decode, the same number as the former per-count limit, so a single count up to that still passes; the MAC and a PBKDF2 spend their count once, a PKCS#12 PBE twice (key and IV). Conformance case work-budget-total: openssl -iter 4000000 for key, certificates and MAC. Interop matrix regenerated 2026-11-05: go core 29/29, go legacy 57/57, rust 57/57; OpenSSL, pyca/cryptography and the JDK decode the new case, having no budget.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
spec/pkcs12 P12-036 is a work budget of 10,000,000 iterations per decode across all derivations; go/pkcs12 and rust/ti-pkcs12 enforce it before each derivation, with a conformance case and tests named after the rule.
<!-- SECTION:FINAL_SUMMARY:END -->
