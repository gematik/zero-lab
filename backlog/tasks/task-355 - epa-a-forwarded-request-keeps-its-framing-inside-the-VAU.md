---
id: TASK-355
title: 'epa: a forwarded request keeps its framing inside the VAU'
status: To Do
assignee: []
created_date: '2026-11-16T22:52:00Z'
labels: []
dependencies: []
priority: high
ordinal: 370000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
`forwardToVAU` (`epa/proxy.go:434-484`) builds the inner request from the client's body and headers, and `vau.Channel.EncryptRequest` serialises it with `httputil.DumpRequest`. For a chunked request the inner message has a body but neither `Content-Length` nor `Transfer-Encoding` (verified), so the Aktensystem reads the body as whatever follows: a smuggled second request inside the VAU or a lost body. servers.md rule 28, "Headers" (request smuggling, RFC 9112 §6.3). Found by the rule 28 audit of TASK-321 (2026-11-17).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 the inner request always carries the exact `Content-Length` of the body it is sent with, and client `Content-Length`/`Transfer-Encoding`/hop-by-hop headers are never copied into it.
- [ ] #2 a test sends a chunked request through the proxy to a fake VAU and checks the inner message's framing and body.
<!-- AC:END -->
