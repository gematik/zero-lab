---
id: TASK-220
title: 'jwz: RFC 7517 deviations in JWK Sets and key use'
status: Done
assignee: []
created_date: '2026-11-05T21:54:00Z'
updated_date: '2026-11-06T07:28:00Z'
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
- [x] #1 each deviation is either fixed with a test named after its section or recorded as a deliberate choice with the reason in jwz's docs
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Fix all four, tests named after the section: 5 a key missing required members, with a member of the wrong type or bad base64 is skipped (duplicate members and non-object entries still fail the set); 4.3 duplicate key_ops refused at parse; 4.3 use and key_ops must agree (sig: sign/verify; enc: encrypt, decrypt, wrapKey, unwrapKey, deriveKey, deriveBits); 4.2/4.3 SoftwareKey::from_jwk refuses use other than sig and key_ops without sign/verify, JWE recipients and SymmetricKey check key_ops too. Release notes.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
87e836a9: all four fixed. Jwk::allows(KeyPurpose) checked by SoftwareKey, SoftwareAgreementKey, SymmetricKey and JWE encryption; key_ops duplicates and use/key_ops conflicts refused at parse; JwkSet skips unreadable keys (UnsupportedKeyType, MissingMember, InvalidMember, Base64), a duplicate member or a non-object entry still fails the set. The old test asserting the opposite of §5 was replaced. Tests rfc_7517_4_2_, rfc_7517_4_3_, rfc_7517_5_.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
All four RFC 7517 deviations fixed with tests named after their sections: sets skip unreadable keys (§5), key_ops unique and consistent with use (§4.3), use/key_ops bind a key via Jwk::allows(KeyPurpose) in every key constructor and JWE encryption (§4.2).
<!-- SECTION:FINAL_SUMMARY:END -->
