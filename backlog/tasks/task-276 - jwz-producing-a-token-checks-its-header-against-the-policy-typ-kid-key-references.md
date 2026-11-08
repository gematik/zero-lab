---
id: TASK-276
title: >-
  jwz: producing a token checks its header against the policy (typ, kid, key
  references)
status: Done
assignee: []
created_date: '2026-11-08T15:20:00Z'
updated_date: '2026-11-08T17:37:00Z'
labels:
  - jwz
  - security
milestone: m-1
dependencies: []
priority: high
ordinal: 292000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Found by TASK-258 (RFC 8725 §3.11, producer side). jws::sign, sign_async, jws::json::sign and jwe::encrypt check algorithm and curve against the policy (TASK-271) but not the header: a profile with a typ signs a token without it and then refuses it, contradicting the README's claim that jwz never produces what its profile refuses. The same holds for require_kid and key_references. TASK-269 (RFC 10070's client-authentication+jwt) needs it.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 sign and encrypt (compact and JSON) run the policy's header checks (typ, require_kid, key references, crit) on the header they produce, before signing or encrypting, and refuse with PolicyViolation
- [x] #2 tests named after RFC 8725 §3.11 prove that a profile with a typ neither produces nor accepts a token without it
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Policy::check_produced_jws/_jwe run check_common (typ, require_kid, key references, crit, b64; zip for JWE) on the header jwz is about to sign or encrypt under: compact before signing, JWE before key agreement, JSON per signature or per recipient's visible header. Five tests that built tokens with headers strict refuses (x5c, jwk, crit) now produce under a profile that allows them and still test strict's refusal; the b64 test builds its tokens by hand, since jwz produces no b64 token. New test rfc_8725_3_11_a_producer_writes_no_header_its_profile_refuses. Docs: guide (profile section, RFC 8725 table), README, ADR 0001, release notes (breaking), encrypt docs.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
sign and encrypt run the policy's header checks (typ, required kid, key references, crit, b64, zip) on the header they produce before signing or key agreement; a profile with a typ no longer signs a token without it.
<!-- SECTION:FINAL_SUMMARY:END -->
