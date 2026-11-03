---
id: TASK-195
title: 'oidf: API key transport and TLS'
status: To Do
assignee: []
created_date: '2026-11-02T22:59:00Z'
labels:
  - go
  - security
dependencies: []
priority: medium
ordinal: 205000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
AddAPIKeyTransport matches HasSuffix without a dot, so xdev.gematik.solutions gets the key. It reads API_KEY from the environment in a library. transportWithTLS drops the base client's RootCAs. ServeSignedJwks publishes a nested keys shape that this repo's own ParseKeySet refuses.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The key goes only to the intended host, from the host's configuration; the signed JWKS is standard, checked against a live federation
<!-- AC:END -->
