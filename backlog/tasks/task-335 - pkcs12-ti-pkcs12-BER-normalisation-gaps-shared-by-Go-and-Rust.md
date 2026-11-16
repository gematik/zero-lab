---
id: TASK-335
title: 'pkcs12, ti-pkcs12: BER normalisation gaps shared by Go and Rust'
status: Done
assignee: []
created_date: '2026-11-15T10:12:00Z'
updated_date: '2026-11-16T23:26:00Z'
labels:
  - pkcs12
  - rust
  - go
dependencies: []
ordinal: 350000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Found by the review of TASK-329's ber.rs (2026-11-15); the same in go/pkcs12/internal/ber: (1) a BER-segmented publicKey [1] IMPLICIT BIT STRING in a PrivateKeyInfo stays constructed, since only the schema knows it is a string (as P12-005 describes for other implicit strings), so P12-041 refuses it against P12-002's every layer; (2) a BIT STRING with unused bits above 7, or unused bits without content, passes through, and the PrivateKeyInfo check reads [1] as Any; (3) tags in a non-minimal high-tag-number form are not normalised; (4) Rust counts the 64-level depth bound from the key bag's value, Go from the safe, so Rust allows a few more levels inside a key bag.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Each gap is fixed in both languages or written into spec/pkcs12 as accepted, with a corpus case or test per gap
<!-- AC:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
All four gaps fixed in both languages: a segmented publicKey [1] is joined; BIT STRING segments with more than 7 unused bits or bits without content are refused; non-minimal high tags refused in Go as in Rust; depth counted per layer from the outermost element (P12-004), Rust now normalising PFX, authSafe and every safe. New corpus case friendly-names-segmented; interop matrix rerun.
<!-- SECTION:FINAL_SUMMARY:END -->
