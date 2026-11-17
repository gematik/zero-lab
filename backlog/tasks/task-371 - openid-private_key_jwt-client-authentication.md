---
id: TASK-371
title: 'openid: private_key_jwt client authentication'
status: To Do
assignee: []
created_date: '2026-11-17T06:45:00Z'
labels:
  - openid
  - oauth
  - keys
dependencies: []
priority: low
ordinal: 386000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
`go/openid/client.go:122-124` authenticates only with `client_secret_post`, and `Config.Validate` requires a secret (`client.go:186-197`). RFC 9700 §2.5 RECOMMENDS asymmetric client authentication (private_key_jwt, RFC 7523). The PDP backend and oidf already use it, while generic OIDC providers in pep cannot. Found by the RFC 9700 audit of TASK-259 (2026-11-17).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 go/openid supports `private_key_jwt` with a key given as a signing function (keys.md). It is chosen when the provider's metadata lists it and a key is configured. Tests named after RFC 7523 §2.2 and RFC 9700 §2.5.
<!-- AC:END -->
