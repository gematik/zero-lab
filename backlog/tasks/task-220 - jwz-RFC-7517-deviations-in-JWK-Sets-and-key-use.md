---
id: TASK-220
title: 'jwz: RFC 7517 deviations in JWK Sets and key use'
status: To Do
assignee: []
created_date: '2026-11-05T21:54:00Z'
updated_date: '2026-11-06T06:43:00Z'
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

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Fix all four, tests named after the section: 5 a key missing required members, with a member of the wrong type or bad base64 is skipped (duplicate members and non-object entries still fail the set); 4.3 duplicate key_ops refused at parse; 4.3 use and key_ops must agree (sig: sign/verify; enc: encrypt, decrypt, wrapKey, unwrapKey, deriveKey, deriveBits); 4.2/4.3 SoftwareKey::from_jwk refuses use other than sig and key_ops without sign/verify, JWE recipients and SymmetricKey check key_ops too. Release notes.
<!-- SECTION:PLAN:END -->
