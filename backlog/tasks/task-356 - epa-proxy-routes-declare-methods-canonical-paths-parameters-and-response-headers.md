---
id: TASK-356
title: >-
  epa: proxy routes declare methods, canonical paths, parameters and response
  headers
status: In Progress
assignee: []
created_date: '2026-11-16T22:52:00Z'
updated_date: '2026-11-22T09:41:00Z'
labels: []
dependencies:
  - TASK-360
priority: medium
ordinal: 371000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Six routes in `epa/proxy.go:322-335` have no method pattern; `{path...}` is used decoded, so `%3F`, `%23`, `%2e%2e` and `%2F` change the inner request (`proxy.go:434-451`) and `providerURL` repairs `..` (`proxy.go:404-414`); the query is forwarded raw; the insurant VAU route skips the KVNR check (`proxy.go:630-645`); upstream response headers are copied wholesale (`proxy.go:383, 475`). servers.md rule 28, "Method and path", "Parameters" and "Output". Found by the rule 28 audit of TASK-321 (2026-11-17).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 each route accepts its declared methods only; a forwarded path with encoded separators, dot segments or characters outside its grammar, a repeated query key and an insurant ID outside the KVNR grammar get 400; only an allowlist of response headers is relayed.
- [ ] #2 fuzz targets over the forwarded path/query handling and `providerURL` assert that the target stays on the provider and under its path.
<!-- AC:END -->
