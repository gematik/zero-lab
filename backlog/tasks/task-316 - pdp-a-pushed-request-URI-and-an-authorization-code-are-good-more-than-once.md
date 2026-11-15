---
id: TASK-316
title: 'pdp: a pushed request URI and an authorization code are good more than once'
status: Done
assignee: []
created_date: '2026-11-14T20:20:00Z'
updated_date: '2026-11-15T11:13:00Z'
labels: []
dependencies: []
ordinal: 331000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Found by zeta-pdp-go while reading go/pdp as prior art (2026-11-14, at 76b3bc8c). Read in the code, not reproduced by a test.

A session's RequestURI (set at authorize.go:235) and Code (set at authorize.go:326) are never cleared. The lookups by request_uri and by code consume their index key with Take, but SaveAutzhServerSession writes the index key of every non-empty field again (cmd/zero-pdp/sessions.go:107 for the code, :113 for the request URI). So:
- after /auth has consumed the request_uri, the save at authorize.go:198 makes it resolvable again;
- after the token endpoint has consumed the code, the save at token.go:308 makes it redeemable again, with the same code_verifier, until the session's TTL (15 minutes) ends.

RFC 6749 Section 4.1.2 asks that a code is used once and that a second use is denied; RFC 9126 Section 7.3 that a request_uri is used once. par_test.go:83 tests the store, not the path through the handlers.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 A request_uri and a code are refused at their second use, in a test through the HTTP handlers; the fields are cleared, or the indexes are not written again, when they are consumed
<!-- AC:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
The authorization endpoint clears session.RequestURI and the token endpoint session.Code right after their Take, so the next save does not index them again; tests through the HTTP handlers, also across replicas, fail without the fix. Token revocation on reuse is TASK-330, the refresh-token race TASK-331. Merged at d8f24089.
<!-- SECTION:FINAL_SUMMARY:END -->
