---
id: TASK-359
title: >-
  zaddy: enforce_policy refuses non-canonical paths and checks htu on the path
  as received
status: Done
assignee: []
created_date: '2026-11-16T22:52:00Z'
updated_date: '2026-11-22 14:25'
labels: []
dependencies:
  - TASK-360
priority: medium
ordinal: 374000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
enforce_policy (`zaddy/enforce_policy.go:76-84`) relies on Caddy's matchers, which normalise an encoded or case-folded path into the protected route (verified gated, but matched after repair and forwarded raw), and pep's DPoP `htu` check uses the request's path after any Caddy rewrite (`pep/pep.go:401`). servers.md rule 28, "Method and path". Found by the rule 28 audit of TASK-321 (2026-11-17).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 enforce_policy answers 400 to a path with encoded separators, dot segments or double encoding, and the DPoP `htu` is the configured origin plus the original request path.
- [x] #2 a Caddy integration test pins both.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
2026-11-22: AC #2 is met by tests of the handler with Caddy's original-request context key, as Caddy hands a rewritten request on, not by a caddytest server.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
zaddy's enforce_policy judges the path the client sent, which Caddy keeps under caddyhttp.OriginalRequestCtxKey: httpguard.CheckPath refuses a non-canonical one with 400 before any enforcer runs (encoded separators, dot segments, double encoding, encoded unreserved, empty segments), and the enforcer sees the request with that URL, so pep's DPoP htu is the configured origin plus the path as sent; the next handler still gets Caddy's rewritten request. Tests: TestServerRule28_EnforcePolicyRefusesANonCanonicalPathAsReceived, TestRFC9449_4_3_TheEnforcerSeesThePathTheClientSent. zaddy requires httpguard v0.2.0.
<!-- SECTION:FINAL_SUMMARY:END -->
