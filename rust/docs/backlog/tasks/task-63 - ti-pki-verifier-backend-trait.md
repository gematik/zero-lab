---
id: TASK-63
title: 'ti-pki: verifier backend trait'
status: To Do
assignee: []
created_date: '2026-10-14 20:43'
labels:
  - ti-pki
  - keys
dependencies: []
references:
  - rust/docs/design.md
priority: medium
ordinal: 61000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Signature verification is pluggable only at the algorithm level; a verifier backend trait like jwz's would let a FIPS or WebCrypto host verify certificates.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 a verifier backend trait in ti-pki with the RustCrypto implementation as default, decided before ti-pki 1.0
<!-- AC:END -->
