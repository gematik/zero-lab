---
id: TASK-56
title: 'Dependencies: scrypt and salsa20 through pkcs5''s pbes2 feature'
status: Done
assignee: []
created_date: 2026-10-14 20:43
updated_date: '2026-11-01T15:18:00Z'
labels:
  - ti-pkcs12
  - deps
milestone: m-0
dependencies: []
references:
  - docs/conventions/dependencies.md
  - rust/docs/design.md
priority: medium
ordinal: 54000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
pkcs5's pbes2 feature pulls scrypt and salsa20, though PKCS#12 never needs scrypt (P12-030).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 scrypt and salsa20 out of the tree through a pkcs5 feature split, an upstream change, or a recorded known compromise
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Decided by the maintainer: option B, pkcs5 replaced, no upstream change. pbkdf2, aes and cbc were already in the tree through pkcs5, so no new crate. Old and new compared directly before pkcs5 went: spec/pkcs12 conformance 56 of 56 on both; 58 corpus files decode alike; 42 encoded files byte-identical; 300,000 mutated PBES2 parameter sets: same result except keyLength mismatch (decryption failed, now malformed, P12-032), parameters that do not decode (unsupported, now malformed), salts above 32 bytes (unsupported, now read), and the display name of an unknown cipher, which now shows its OID. fuzz-ti-pkcs12 90 s, 1.6M runs, no finding.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
ti-pkcs12 reads and writes PBES2 itself in src/pbes2.rs over pbkdf2, aes and cbc. pkcs5, scrypt and salsa20 are gone from the tree, the scrypt unsafe exception too. just check green.
<!-- SECTION:FINAL_SUMMARY:END -->
