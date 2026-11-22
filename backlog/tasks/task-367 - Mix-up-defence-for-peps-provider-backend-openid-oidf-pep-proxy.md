---
id: TASK-367
title: 'Mix-up defence for pep''s provider backend: the gap recorded'
status: Done
assignee: []
created_date: '2026-11-17T06:44:00Z'
updated_date: '2026-11-22 12:17'
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
- [x] #1 Which TI IdPs send iss is checked against gemSpec and their metadata, and noted in the task
- [x] #2 The gap, the reason it is accepted and the defences in force are written down in the pep/proxy docs
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
2026-11-22, AC #3: no TI specification asks for or mentions the RFC 9207 iss parameter or mix-up: gemSpec_IDP_Sek 3.3.0, gemSpec_IDP_FD 2.2.0, gemSpec_IDP_FedMaster 1.4.3, gemSpec_IDP_Dienst 2.2.0, gemSpec_ZETA 1.3.2 and draft 2.0.0_CC, gemKPT_TI-Föderation 1.0.0. Live metadata of 2026-11-22: authorization_response_iss_parameter_supported is absent in the openid_provider metadata of TK RU2 and TK RU (idbroker.tk.ru2/ru.nonprod-ehealth-id.de), RISE (oidc.vau.ru.tiru.idp.rise-service.de/999000008), BITMARCK (www.idp.ru.iam-bms.de/995530444) and in the discovery document of the IDP-Dienst (idp-ref.app.ti-dienste.de). So no TI IdP can be expected to send iss; AC #2's fallback applies: distinct redirect URIs per issuer (RFC 9700 §4.4.2.2), or per provider kind with the gap recorded. Note: zerobin's edge already receives /gemidp-callback (idpd) and /op-callback (OIDF) apart and rewrites both to /oauth2/callback, so pep loses which one was used.

2026-11-22: variant C by the maintainer's decision: neither the RFC 9207 check nor redirect URIs per issuer or per provider kind are built; the gap is recorded in go/pep/proxy/docs/DESIGN.md §3 ('Mix-up: a gap accepted for now').
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
No TI IdP sends or announces the RFC 9207 iss and no gematik specification asks for it (checked 2026-11-22). By the maintainer's decision no mix-up defence is built for now; DESIGN.md §3 records the gap against RFC 9700 Section 2.1 and what limits it: the code goes only to the token endpoint of the provider the session's state names, federation providers come only from the master's signed IdP list, and the ID token's iss must be that provider. Reopen if a TI provider starts sending iss.
<!-- SECTION:FINAL_SUMMARY:END -->
