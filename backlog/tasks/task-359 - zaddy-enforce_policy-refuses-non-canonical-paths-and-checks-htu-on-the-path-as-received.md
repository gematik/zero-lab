---
id: TASK-359
title: >-
  zaddy: enforce_policy refuses non-canonical paths and checks htu on the path
  as received
status: To Do
assignee: []
created_date: '2026-11-16T22:52:00Z'
updated_date: '2026-11-16T22:52:00Z'
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
- [ ] #1 enforce_policy answers 400 to a path with encoded separators, dot segments or double encoding, and the DPoP `htu` is the configured origin plus the original request path.
- [ ] #2 a Caddy integration test pins both.
<!-- AC:END -->
