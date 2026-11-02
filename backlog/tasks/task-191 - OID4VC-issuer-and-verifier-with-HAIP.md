---
id: TASK-191
title: OID4VC issuer and verifier with HAIP
status: To Do
assignee: []
created_date: '2026-11-02T20:13:00Z'
labels:
  - go
  - security
dependencies: []
priority: medium
ordinal: 201000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
An OpenID4VCI issuer and OpenID4VP verifier for the EUDI wallet, with the HAIP profile and further hardening. /Users/serg/Development/gematik/eudi-demo (verifier-kotlin) is the behaviour reference. Whether and when it moves to Go is this task's first decision. In Go it would be go/oid4vc (sdjwt, mdoc, dcql, issuer, verifier) on dpop, nonce, the oauth root and go-jose; not oauth/oidc, idpd, oidf, tipki or pdp.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Requirements taken from the current specifications; language and module decided
<!-- AC:END -->
