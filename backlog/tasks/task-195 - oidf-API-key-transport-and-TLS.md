---
id: TASK-195
title: 'oidf: API key transport and TLS'
status: In Progress
assignee: []
created_date: '2026-11-02T22:59:00Z'
updated_date: '2026-11-05T18:30:00Z'
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

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Done: the key goes only to https hosts below .dev.gematik.solutions, from api_key_path in the relying party configuration; API_KEY is no longer read, so deployments must set api_key_path. Mutual TLS keeps the base client's RootCAs and MinVersion. Open, so the criterion stays unticked: the signed JWKS shape, which needs a check against a live federation.
<!-- SECTION:NOTES:END -->
