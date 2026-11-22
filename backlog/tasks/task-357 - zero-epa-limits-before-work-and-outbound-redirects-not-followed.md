---
id: TASK-357
title: 'zero-epa: limits before work, and outbound redirects not followed'
status: Done
assignee: []
created_date: '2026-11-16T22:52:00Z'
updated_date: '2026-11-22T10:13:00Z'
labels: []
dependencies:
  - TASK-360
priority: medium
ordinal: 372000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
`epa/cmd/zero-epa/cmd/proxy.go:97` sets only `ReadHeaderTimeout` and no `MaxHeaderBytes`; forwarded bodies have no `MaxBytesReader` and are buffered whole by `DumpRequest` (`epa/vau/channel.go:196-198`); no Host check. The Aktensystem client follows redirects (`epa/session.go:248-260`), and `GetRecordStatus`/`GetConsentDecisionInformation` never close their response bodies (`epa/information.go:34-84`). servers.md rule 28, "Limits before work" and "Outbound responses". Found by the rule 28 audit of TASK-321 (2026-11-17).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 the server has explicit header, body (the ePA document limit for forwarded bodies) and timeout bounds and a Host check; the outbound client refuses redirects; every response body is closed.
- [x] #2 tests pin an oversized body, a redirecting Aktensystem and a foreign Host as refused.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
2026-11-22, branch fix/epa-rule28 (33d80af4). zero-epa server: MaxHeaderBytes 32 KiB, ReadHeaderTimeout 10s, ReadTimeout 5 min, WriteTimeout 10 min, IdleTimeout 2 min; Host checked against the config's hosts (default: the loopback names of the listen port), 421 otherwise; path checked before the router. Body limit ProxyConfig.MaxRequestBytes (max_request_bytes), default DefaultMaxRequestBytes = one 25 MiB document (A_14937) base64-encoded plus 1 MiB, about 34.3 MiB; read before any session, 413 above it. A submission up to the 250 MiB package limit needs a larger setting. The Aktensystem client refuses redirects (ErrRedirect), which also covers the VAU channel; every response body is closed. Tests: TestServerRule28_AnOversizedBodyIsRefusedBeforeWork, TestServerRule28_ARedirectingAktensystemIsRefused, TestServerRule28_AForeignHostOrANonCanonicalPathIsRefused.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Merged in bbf8921f (fix/epa-rule28). zero-epa has explicit header, read, write and idle bounds, a Host check against the configured hosts (default: loopback names of the listen port) and a path check before the router; forwarded bodies are bounded by max_request_bytes (default one 25 MiB document, base64, plus 1 MiB) before any session is opened; the Aktensystem client refuses redirects and every response body is closed.
<!-- SECTION:FINAL_SUMMARY:END -->
