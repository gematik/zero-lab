---
id: TASK-354
title: 'zero-pep-proxy: the server checks Host and bounds headers and its own cookie'
status: In Progress
assignee: []
created_date: '2026-11-16T22:52:00Z'
updated_date: '2026-11-19 08:32'
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
- [x] #1 a request whose Host is not a configured name gets 400 (or 421); `MaxHeaderBytes` is explicit; the session cookie value must be the 43-character base64url token before the store is asked.
- [x] #2 a test pins each refusal.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Host: proxy.Config.Hosts; Server.Handler answers 421 (RFC 9110 Section 15.5.20) to a request whose Host is not one of them, before the mux, so neither /oauth2/* nor a gateway route is reached; httpguard.Host compares byte for byte with the port. zero-pep-proxy sets the host of PEP_PUBLIC_URL and what the new PEP_HOSTS adds (for a proxy in front that sends another Host); CONFIG.md and DOCKERHUB.md name it. The gateway still passes Host on as X-Forwarded-Host, which is now a configured name. A library user that leaves Hosts empty gets no check. Header limit: newHTTPServer sets MaxHeaderBytes to 64 KiB (was Go's default of 1 MiB). Cookie: sessionManager.byToken refuses a value that is not 43 base64url characters before the store is asked, which covers every reader of the session cookie. Tests TestServerRule28_ARequestForAnotherHostIsAnswered421, …_ASessionCookieOfAnotherFormNeverReachesTheStore, …_ARequestHeaderAboveTheLimitIsRefusedBeforeTheHandler, …_TheServedHostsComeFromTheConfiguration. Rollout: a deployment whose front proxy rewrites Host to the service name has to set PEP_HOSTS, or every request is answered 421.
<!-- SECTION:NOTES:END -->
