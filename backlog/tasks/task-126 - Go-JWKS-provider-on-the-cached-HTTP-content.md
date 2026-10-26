---
id: TASK-126
title: 'Go: JWKS provider on the cached HTTP content'
status: To Do
assignee: []
created_date: '2026-10-21 07:14'
labels:
  - go
  - security
dependencies:
  - TASK-125
priority: high
ordinal: 137000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
jwx brings its own JWKS cache (jwk.Cache over httprc, background goroutines), used by oauth/oidc; go-jose (TASK-95) has none. A JWKS provider on the shared cached HTTP content: the key for a kid from the cached set; on an unknown kid one refetch, at most once per configured interval (key rotation without a fetch per forged kid); a size limit on the set and a limit on its keys; keys filtered by use=sig and by the algorithms the caller allows; keys as go-jose JSONWebKey. Consumers: oauth/oidc (ID tokens of OpenID providers), oidf (federation keys, where they come from a URL), pdp (client keys for private_key_jwt where registered by URL). Outbound fetches follow TASK-75's SSRF rules.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 a JWKS provider on the cached HTTP content: kid lookup, rate-limited refetch on an unknown kid, size limits, use and algorithm filtering, tested against a local server (rotation, forged kid, oversized set, origin down within stale-if-error)
- [ ] #2 oauth/oidc uses it instead of jwx's jwk.Cache
<!-- AC:END -->
