---
id: TASK-230
title: 'jwz: BP256R1 key generation fails about once in 5,500'
status: To Do
assignee: []
created_date: '2026-11-06T08:19:00Z'
labels:
  - jwz
  - ti-jwz
  - bug
dependencies: []
priority: high
ordinal: 241000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Found by just check on the TASK-97 branch (ti-idpd a_20526 failed once with Crypto(Rng)). jwz/src/keys/software.rs random_scalar tries 8 random strings, assuming each is a valid scalar except with negligible probability. That holds for P-256 (order near 2^256), not for brainpoolP256r1, whose order is about 0.66 * 2^256: a third of all draws fail, so SoftwareKey::generate(BP256R1) fails with probability 0.34^8, about 1/5500. ti-jwz's brainpool ECDH generation already allows 64 draws for this reason.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 a BP256R1 key is generated even when many draws fall outside the group order, with a deterministic test
<!-- AC:END -->
