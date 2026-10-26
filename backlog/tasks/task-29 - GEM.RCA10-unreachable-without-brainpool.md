---
id: TASK-29
title: GEM.RCA10 unreachable without brainpool
status: Done
assignee: []
created_date: '2026-10-10 17:08'
updated_date: '2026-10-11 07:49'
labels:
  - ti-pki
dependencies: []
priority: low
ordinal: 25000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
From the GEM.RCA7 anchor the A_28419 cross-certificate walk under algorithms::NIST stops at the first brainpool signature: it keeps GEM.RCA7 and GEM.RCA6 only. GEM.RCA10 is a P-256 root a NIST-only client could use, but the walk reaches the newer roots only through RCA8's brainpool cross signature, so --nist-only never reaches RCA9 (RSA) or RCA10.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 decided whether NIST-only trust needs RCA9/RCA10 (e.g. a pinned anchor, or a brainpool-checked walk that exports non-brainpool roots), and implemented or closed with the reason
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Decided 2026-10-11 (user): the walk always runs with brainpool; only the resulting CAs are narrowed to a NIST subset. ti --nist-only loads and verifies roots and TSL with the full preset, then keeps roots and TSL CAs whose own key algorithms::NIST supports (TrustStore::subset). Prod subset: GEM.RCA7, RCA9, RCA10, RCA6, RCA2 and 29 TSL CAs; pki verify --nist-only validates against it with NIST algorithms.
<!-- SECTION:NOTES:END -->
