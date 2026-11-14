---
id: TASK-320
title: >-
  docs: servers.md rule 28, every HTTP message is checked before the logic sees
  it
status: Done
assignee: []
created_date: '2026-11-14T21:07:00Z'
updated_date: '2026-11-14T21:09:00Z'
labels:
  - docs
  - servers
dependencies: []
ordinal: 335000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The maintainer asked (2026-11-14) for the rules of checking HTTP requests in servers.md. Rule 2 names strict input handling in one line; what it means for an HTTP request (method, path, query, headers, body, values, cookies, redirects, errors) and for the responses of outbound calls is not written down, and TASK-315 step 5b implements it for oidf. New rule 28 at the end so cited numbers stay stable; the count in CLAUDE.md becomes 28.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 servers.md has rule 28 with the checks for inbound requests and outbound responses, fuzzing of the checks, and reject-never-repair
- [x] #2 CLAUDE.md and any other count of the rules say 28
<!-- AC:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
servers.md rule 28 added at the end (cited numbers stable): inbound requests and outbound responses checked before use — reject never repair, limits before work, methods and canonical paths, declared parameters (repeats refused), Host, Content-Type, smuggling, strict bodies, value grammars, exact redirects, cookies, output encoding, errors without values, one implementation per language with property-asserting fuzz targets. CLAUDE.md says 28 rules; go/docs/design.md §10 maps it to Go (net/http drops Content-Length under chunked per RFC 9112 §6.3, so the rule allows refuse or drop). Merged as 404ea933.
<!-- SECTION:FINAL_SUMMARY:END -->
