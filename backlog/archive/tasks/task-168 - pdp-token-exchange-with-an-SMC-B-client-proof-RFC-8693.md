---
id: TASK-168
title: 'pdp: token exchange with an SMC-B client proof (RFC 8693)'
status: To Do
assignee: []
created_date: '2026-11-01T16:11:00Z'
labels:
  - go
  - pdp
  - security
dependencies:
  - TASK-120.4
  - TASK-120.6
  - TASK-97
priority: medium
ordinal: 178000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The PDP has authorization_code, client_credentials and refresh_token (go/pdp/authzserver/token.go) and authenticates clients with private_key_jwt over ES256 only. Token exchange lets a client that holds an SMC-B prove it (brainpoolP256r1 signature over an assertion) and receive a token whose subject is the Telematik-ID with the profession OIDs as claims. The certificate check (chain to a TSL-listed CA under a roots.json root, C.HCI.AUT profile and key rules, OCSP, admission extension) is not implemented in Go and will not be: decision-10 routes it to the stateless ti-pki-helper in the PDP's image, reached over stdio or a Unix socket (TASK-120.4, TASK-120.6), under the rule set of spec/pki-validation (TASK-97). Go verifies the assertion's signature against the verified certificate's key through go/brainpool, binds the token with DPoP as the other grants do, and hands the verified attributes to the policy (OPA task). Rules: docs/design/servers.md 2, 10, 15, 16; docs/interop.md decision procedure.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 the grant urn:ietf:params:oauth:grant-type:token-exchange accepts an SMC-B assertion only after the helper's verdict is valid for the hci-aut profile with OCSP good; every other verdict is a uniform error
- [ ] #2 the issued token carries the Telematik-ID and profession OIDs from the verdict, is DPoP-bound and short-lived; introspection reflects it
- [ ] #3 requirement-named tests against a fake helper and the real one with the spec corpus; fuzz target for the assertion parser; e2e in go/pdp/e2e
<!-- AC:END -->
