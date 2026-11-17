---
id: TASK-367
title: Mix-up defence for pep's provider backend (openid, oidf, pep/proxy)
status: To Do
assignee: []
created_date: '2026-11-17T06:44:00Z'
labels:
  - openid
  - oidf
  - pep-proxy
  - security
  - oauth
dependencies: []
priority: medium
ordinal: 382000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The provider backend talks to several authorization servers: static OIDC IdPs, the idpd client and every OIDF federation IdP (`go/pep/proxy/backend_provider.go:63-68`). All of them come back through one `/oauth2/callback` (`cmd/zero-pep-proxy/config.go:53`). The callback (`proxy.go:440-462`) reads neither the RFC 9207 `iss` parameter nor which path the response arrived on. go/openid has no check of an authorization response's `iss`. The ID token `iss` check (`go/openid/claims.go:81`, `go/oidf/client.go:228`) runs after the code was already sent to the stored issuer's token endpoint, too late against mix-up (RFC 9700 §4.4.2.1). RFC 9700 §2.1 REQUIRES a mix-up defence for a client of more than one AS. Federation admission (`go/oidf/client.go:62-71`) limits the attacker to federation members. Found by the RFC 9700 audit of TASK-259 (2026-11-17).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 go/openid offers the RFC 9207 check: `iss` present when the AS metadata announces `authorization_response_iss_parameter_supported`, and equal to the stored issuer. Tests named after RFC 9207 §2.4.
- [ ] #2 pep's callback compares the response's `iss` with the session's `IDPIss` before `Complete`, and refuses a mismatch. Where an IdP sends no `iss`, distinct per-issuer redirect URIs (RFC 9700 §4.4.2.2) are used instead, or the gap is recorded for that IdP.
- [ ] #3 Which TI IdPs (IDP-Dienst, federation IdPs) send `iss` is checked against gemSpec and noted in the task.
<!-- AC:END -->
