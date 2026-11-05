---
id: TASK-218
title: 'ti-pkcs12: tests for the 37 surviving mutants'
status: To Do
assignee: []
created_date: '2026-11-05T21:53:00Z'
labels:
  - tests
  - ti-pkcs12
dependencies: []
ordinal: 225000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
cargo-mutants 27.1.0 on ti-pkcs12 (default features, main at e15366b0): 37 missed, 136 caught, 5 timeouts, 54 unviable, score 79.2% against the proposed threshold of 80% (TASK-53). Among the survivors: Error::is_wrong_password returning a constant, the KEY_BAG and SAFE_CONTENTS_BAG arms of collect and the TRUSTED_KEY_USAGE arm of attributes deleted, the length guard of is_pkcs12, asn1::one, the EncryptedData version check, and the PKCS#12 PBE guard in decrypt. Full list: just mutants ti-pkcs12, mutants.out/missed.txt.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 each surviving mutant is killed by a test named after the rule it breaks, or marked equivalent with the reason
- [ ] #2 just mutants-record ti-pkcs12 reaches the crate's threshold
<!-- AC:END -->
