---
id: TASK-220
title: 'jwz: RFC 7517 deviations in JWK Sets and key use'
status: To Do
assignee: []
created_date: '2026-11-05T21:54:00Z'
labels:
  - jwz
dependencies: []
ordinal: 227000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Found while writing TASK-51's tests: a JWK Set fails as a whole on a key missing required members, where RFC 7517 Section 5 says such keys SHOULD be ignored (only an unknown kty is skipped today); duplicate key_ops values are accepted (Section 4.3: MUST NOT); use and key_ops are not checked for consistency (Section 4.3); use is enforced only when encrypting a JWE, so a key marked use=enc still signs and verifies.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 each deviation is either fixed with a test named after its section or recorded as a deliberate choice with the reason in jwz's docs
<!-- AC:END -->
