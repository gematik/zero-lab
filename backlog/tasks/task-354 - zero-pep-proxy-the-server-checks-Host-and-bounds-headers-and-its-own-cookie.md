---
id: TASK-354
title: 'zero-pep-proxy: the server checks Host and bounds headers and its own cookie'
status: To Do
assignee: []
created_date: '2026-11-16T22:52:00Z'
updated_date: '2026-11-16T22:52:00Z'
labels: []
dependencies:
  - TASK-360
priority: medium
ordinal: 369000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
`cmd/zero-pep-proxy/main.go:298-303` sets no `MaxHeaderBytes` and nothing checks `Host` against the configured `PEP_PUBLIC_URL`; the gateway passes the client's Host upstream as `X-Forwarded-Host` (`pep/proxy/gateway.go:184`). The session cookie value is hashed and looked up whatever its form (`proxy.go:532-541`). servers.md rule 28, "Limits before work", "Headers" (Host) and "Cookies". Found by the rule 28 audit of TASK-321 (2026-11-17).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 a request whose Host is not a configured name gets 400 (or 421); `MaxHeaderBytes` is explicit; the session cookie value must be the 43-character base64url token before the store is asked.
- [ ] #2 a test pins each refusal.
<!-- AC:END -->
