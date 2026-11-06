---
id: TASK-230
title: 'jwz: BP256R1 key generation fails about once in 5,500'
status: Done
assignee: []
created_date: '2026-11-06T08:19:00Z'
updated_date: '2026-11-06T12:16:00Z'
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
- [x] #1 a BP256R1 key is generated even when many draws fall outside the group order, with a deterministic test
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
On spec/pki-validation (73eedaaa, then try_update): random_scalar draws up to 64 times; ti-jwz test a_bp256r1_key_is_generated_however_many_draws_fall_outside_the_order fails with 8 draws and passes with 64. Merged with the TASK-97 branch.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Merged into main by fast-forward (1f6aa1e6) with TASK-97's branch spec/pki-validation; just check green (820 + 128 tests, deny, vet, stamps).
<!-- SECTION:FINAL_SUMMARY:END -->
