---
id: TASK-171
title: >-
  gemidp: verify the IDP-Dienst certificate against the TSL (Go relying-party
  side)
status: Done
assignee: []
created_date: '2026-11-01T16:11:00Z'
updated_date: '2026-11-02T19:06:00Z'
labels:
  - go
  - gemidp
  - security
dependencies: []
priority: high
ordinal: 181000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
go/gemidp takes the IDP-Dienst's signing key from the x5c of the discovery document and verifies the discovery document, challenge and id_token with it (shared.go:155-193), but never verifies that certificate: shared.go:142 logs 'Certificate of discovery document not verified. Don't trust it in production.' The Rust side does it (TASK-27, done, ti-idpd checks the IDP certificates against the TSL). The servers that use gemidp as relying party (pdp, pep, bff) therefore trust whatever the discovery endpoint presents. Per decision-10 the check goes through the stateless ti-pki-helper (TASK-120.4, TASK-120.6) with the IDP profile, not through a Go implementation. Rules: docs/architecture.md trust from verification only; docs/design/servers.md 16.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 the discovery document's certificate is verified against the TSL with the IDP-Dienst profile and OCSP before its key is used; a failed verdict is a hard error, never a warning
- [x] #2 requirement-named tests with the spec corpus and a fake helper; the warning log line is gone
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
2026-11-02, maintainer: option A, native. Depends on TASK-176. Check both certificates ti-idpd checks: the discovery signer and the token signer in the x5c of the puk_idp_sig JWK, which verifies challenges and id_tokens.

Maintainer, 2026-11-02: both anchor sets compiled in, the environment picks (decision-11). Also: an unnamed or unknown environment refuses to start; puk_idp_enc has no certificate, accepted and recorded as IDPV-004, same as ti-idpd. Live run: both reference IDP certificates pass idpd-sig with OCSP via just gemidp-trust-test. The bundle comes from ti pki trust export, which is on feat/ti-pki-trust-export and not on this branch. go/gemidp replaces go/tipki with ../tipki until the first push and just sync. AC 2 says fake helper from the helper plan; the native path uses a fake trust and a fake IDP instead.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
go/gemidp verifies the discovery signer and puk_idp_sig with idpd-sig and hard-fail OCSP before using their keys; there is no client without trust material. HITL passed against the reference IDP.
<!-- SECTION:FINAL_SUMMARY:END -->
