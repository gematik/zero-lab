---
id: TASK-350
title: 'pep/proxy: the gateway matches routes on the canonical path only'
status: Done
assignee: []
created_date: '2026-11-16T22:52:00Z'
updated_date: '2026-11-18T20:05:00Z'
labels: []
dependencies:
  - TASK-360
priority: high
ordinal: 365000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
`Gateway.match` (`pep/proxy/gateway.go:92-99`) compares the decoded `r.URL.Path` by string prefix with no segment boundary, and strip_prefix (`gateway.go:175-183`) forwards encoded dot segments as literal `/../`. Verified: `/pub/%2e%2e/private/x` on an open route reaches the upstream as `/../private/x`, and `/public/..%2Fprivate/x` passes ungated, so an upstream that resolves either serves a gated route without the gate. servers.md rule 28, "Method and path". Found by the rule 28 audit of TASK-321 (2026-11-17).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 a request whose path holds an encoded `/`, `\` or NUL, a `.`/`..` segment (literal or encoded) or double encoding gets 400 before route matching; a prefix matches only on a segment boundary.
- [x] #2 tests named after the rule pin both, and a fuzz target over route matching and strip_prefix asserts that the forwarded path starts with the matched prefix's upstream path and has no dot segment.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Branch fix/rule28-gaps, a34af115. Gateway.ServeHTTP: httpguard.Path → 400 invalid_request before matching; match uses httpguard.HasPrefix on EscapedPath; strip_prefix trims the escaped path before SetURL joins the upstream path (before, the trim ran after the join and missed when the upstream had a path); validateRoutes refuses a non-canonical prefix. docs/gateway.md: matching. Tests: TestServerRule28_TheGatewayMatchesTheCanonicalPathOnly (both audit attacks and more; fails on the old gateway), TestServerRule28_ARoutePrefixIsACanonicalPath, FuzzGatewayRoute (1 min: what reaches an upstream is under its path, canonical, through /pub only on a segment boundary).
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Merged in c92d0f8d (fix/rule28-gaps). The gateway checks the path as received with httpguard.Path and answers 400 to a non-canonical one before any route matches. A prefix matches on a segment boundary only, strip_prefix trims the escaped path before SetURL, and a non-canonical route prefix is refused at load. Tests: TestServerRule28_TheGatewayMatchesTheCanonicalPathOnly, TestServerRule28_ARoutePrefixIsACanonicalPath, FuzzGatewayRoute. pep/proxy pins httpguard v0.1.0; not yet released.
<!-- SECTION:FINAL_SUMMARY:END -->
